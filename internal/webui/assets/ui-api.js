(function () {
  'use strict';

  const path = '/api/v1/admin/api-keys';
  const pageSize = 15;
  const dateFormat = new Intl.DateTimeFormat('zh-CN', {dateStyle: 'short', timeStyle: 'short'});

  function validNetwork(value) {
    const [ip, bits, ...extra] = value.split('/');
    if (extra.length || (bits !== undefined && !/^\d{1,3}$/.test(bits))) return false;
    if (ip.includes(':')) {
      if (!/^[\da-f:.]+$/i.test(ip) || Number(bits) > 128) return false;
      try {
        return Boolean(new URL('http://[' + ip + ']/').hostname);
      } catch {
        return false;
      }
    }
    const octets = ip.split('.');
    return octets.length === 4 && !(Number(bits) > 32) &&
      octets.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
  }

  function create({fetch, request, notify}) {
    const $ = id => document.getElementById(id);
    const form = $('apiForm');
    const editDialog = $('apiEditDialog');
    const deleteDialog = $('apiDeleteDialog');
    const keyDialog = $('apiKeyDialog');
    const keyValue = $('apiKeyValue');
    let keys = [], page = 0, active = false, generation = 0, pending = false, editing = null;

    const pager = GoNetPager.create($('apiPager'), {
      pageSize,
      onPageChange(index) {
        page = index;
        render();
      }
    });

    function render(message = '暂无 API Key') {
      const result = GoNetPager.paginate(keys, page, pageSize);
      page = result.pageIndex;
      $('apiEmpty').hidden = !result.empty;
      $('apiEmpty').textContent = message;
      $('apiPager').hidden = result.totalPages <= 1;
      pager.render(result);
      const fragment = document.createDocumentFragment();
      for (const key of result.pageItems) {
        const row = fragment.appendChild(document.createElement('tr'));
        for (const text of [key.name, key.description || '—']) {
          const cell = row.insertCell();
          cell.className = 'api-ellipsis';
          cell.textContent = cell.title = text;
        }
        row.insertCell().appendChild(document.createElement('code')).textContent = key.key_preview;
        const addresses = row.insertCell();
        addresses.className = 'api-addresses';
        for (const address of key.allowed_ips) {
          addresses.appendChild(document.createElement('code')).textContent = address;
        }
        const time = row.insertCell().appendChild(document.createElement('time'));
        time.dateTime = key.created_at;
        time.textContent = dateFormat.format(new Date(key.created_at));
        const edit = row.insertCell().appendChild(document.createElement('button'));
        edit.type = 'button';
        edit.className = 'text-button';
        edit.textContent = '编辑';
        edit.setAttribute('aria-label', '编辑 ' + key.name);
        edit.addEventListener('click', () => openForm(key));
      }
      $('apiRows').replaceChildren(fragment);
    }

    async function load() {
      const current = ++generation;
      $('apiError').hidden = true;
      $('apiAdd').disabled = true;
      render('正在读取 API Key…');
      try {
        const response = await fetch(path, {cache: 'no-store'});
        const data = await response.json();
        if (!response.ok) throw Error(data.error?.message || '暂时无法读取 API Key');
        if (active && current === generation) {
          keys = data.keys;
          render();
        }
      } catch (error) {
        if (active && current === generation) {
          $('apiErrorText').textContent = error.message || '暂时无法读取 API Key';
          $('apiError').hidden = false;
          render('API Key 列表暂时不可用');
        }
      } finally {
        if (active && current === generation) $('apiAdd').disabled = false;
      }
    }

    function setFormError(message = '') {
      $('apiFormError').textContent = message;
      $('apiFormError').hidden = !message;
    }

    function setPending(value) {
      pending = value;
      $('apiSave').disabled = value;
      $('apiEditCancel').disabled = value;
      $('apiDelete').disabled = value;
    }

    function openForm(key = null) {
      if (pending || $('apiAdd').disabled) return;
      editing = key;
      $('apiEditTitle').textContent = key ? '编辑 API Key' : '新增 API Key';
      $('apiSave').textContent = key ? '保存修改' : '创建 Key';
      $('apiDelete').hidden = !key;
      $('apiName').value = key?.name ?? '';
      $('apiDescription').value = key?.description ?? '';
      $('apiProfile').value = key?.profile ?? 'topology_read';
      $('apiIPs').value = key?.allowed_ips.join('\n') ?? '';
      setFormError();
      editDialog.showModal();
      $('apiName').focus();
    }

    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (pending) return;
      const name = $('apiName').value.trim();
      const description = $('apiDescription').value.trim();
      const profile = $('apiProfile').value;
      const allowed_ips = $('apiIPs').value.trim().split(/[\s,，]+/u).filter(Boolean);
      if (!name || [...name].length > 100) return setFormError('名称须为 1 到 100 个字符。');
      if ([...description].length > 1000) return setFormError('描述最多 1000 个字符。');
      if (!allowed_ips.length || allowed_ips.length > 64 || !allowed_ips.every(validNetwork)) {
        return setFormError('请填写 1 到 64 个有效的 IP 地址或 CIDR 网段。');
      }
      const id = editing?.id;
      const current = generation;
      setPending(true);
      setFormError();
      try {
        const result = await request(id ? path + '/' + id : path, {name, description, allowed_ips, profile}, id ? 'PATCH' : 'POST');
        if (!active || current !== generation) return;
        editDialog.close();
        if (id) {
          notify('API Key 已更新，权限及白名单已生效。');
        } else {
          page = 0;
          keyValue.value = result.key;
          result.key = '';
          keyDialog.showModal();
          $('apiCopyKey').focus();
        }
        setPending(false);
        load();
      } catch (error) {
        if (active && current === generation) setFormError(error.message || '暂时无法保存 API Key');
      } finally {
        if (active && current === generation) setPending(false);
      }
    });

    $('apiAdd').addEventListener('click', () => openForm());
    $('apiErrorRetry').addEventListener('click', load);
    $('apiEditCancel').addEventListener('click', () => editDialog.close());
    editDialog.addEventListener('cancel', event => { if (pending) event.preventDefault(); });

    $('apiDelete').addEventListener('click', () => {
      if (pending || !editing) return;
      $('apiDeleteName').textContent = editing.name;
      deleteDialog.showModal();
    });

    $('apiDeleteConfirm').addEventListener('click', async () => {
      if (!deleteDialog.open || pending || !editing) return;
      const id = editing.id;
      const current = generation;
      deleteDialog.close();
      setPending(true);
      setFormError();
      try {
        await request(path + '/' + id, undefined, 'DELETE');
        if (!active || current !== generation) return;
        keys = keys.filter(key => key.id !== id);
        editDialog.close();
        notify('API Key 已删除。');
        setPending(false);
        load();
      } catch (error) {
        if (active && current === generation) setFormError(error.message || '暂时无法删除 API Key');
      } finally {
        if (active && current === generation) setPending(false);
      }
    });

    function clearSecret() {
      keyValue.value = '';
      $('apiKeyMessage').textContent = '';
    }

    keyDialog.addEventListener('close', clearSecret);
    $('apiCopyKey').addEventListener('click', async () => {
      if (!keyValue.value) return;
      try {
        if (!navigator.clipboard) throw Error();
        await navigator.clipboard.writeText(keyValue.value);
        if (keyDialog.open) $('apiKeyMessage').textContent = '已复制 Key。';
      } catch {
        if (!keyDialog.open) return;
        keyValue.select();
        $('apiKeyMessage').textContent = document.execCommand('copy') ? '已复制 Key。' : '请手动复制已选中的 Key。';
      }
    });

    function leave() {
      active = false;
      generation++;
      if (!document.body.contains(form)) return;
      setPending(false);
      if (deleteDialog.open) deleteDialog.close();
      if (editDialog.open) editDialog.close();
      if (keyDialog.open) keyDialog.close();
      clearSecret();
      form.reset();
      keys = [];
      page = 0;
    }

    window.addEventListener('pagehide', leave);
    window.addEventListener('pageshow', event => {
      if (event.persisted && document.body.dataset.view === 'api') show();
    });

    function show() {
      active = true;
      load();
    }

    return {show, leave, clear: leave};
  }

  window.GoNetAPI = {create};
})();
