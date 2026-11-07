'use strict';
const form=document.getElementById('loginForm'),username=document.getElementById('username'),password=document.getElementById('password'),button=document.getElementById('loginButton'),errorBox=document.getElementById('loginError'),toggle=document.getElementById('togglePassword');
let submitting=false,checking=true;
const next=new URLSearchParams(location.search).get('next')||'/';
function destination(value){return value==='/'||/^\/\?page=(overview|devices|topology|candidates|probes|settings|api)$/.test(value)?value:'/'}
function busy(value){button.disabled=value;form.setAttribute('aria-busy',String(value));document.getElementById('loginSpinner').hidden=!value;document.getElementById('loginLabel').textContent=value?'登录中…':'登录'}
toggle.addEventListener('click',()=>{const show=password.type==='password';password.type=show?'text':'password';toggle.textContent=show?'隐藏':'显示';toggle.setAttribute('aria-label',show?'隐藏密码':'显示密码');toggle.setAttribute('aria-pressed',String(show))});
form.addEventListener('submit',async event=>{
 event.preventDefault();if(submitting||checking)return;
 errorBox.textContent='';const user=username.value.trim();
 if(!user||!password.value){errorBox.textContent='请输入用户名和密码';(!user?username:password).focus();return}
 submitting=true;busy(true);
 try{
  const response=await fetch('/api/v1/auth/login',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-GoNet-Login':'1'},body:JSON.stringify({username:user,password:password.value,next}),cache:'no-store'});
  const data=await response.json();
  if(!response.ok){errorBox.textContent=response.status===401?'用户名或密码错误':response.status===429?'登录尝试过于频繁，请稍后重试':data.error?.message||'暂时无法登录，请稍后重试';return}
  password.value='';location.replace(destination(data.redirect_to));
 }catch{errorBox.textContent='网络不可用，请检查连接后重试'}finally{submitting=false;busy(false)}
});
// Check an existing session without ever asking the topology backend for data.
button.disabled=true;
fetch('/api/v1/auth/me',{cache:'no-store',credentials:'same-origin'}).then(response=>{if(response.ok)location.replace(destination(next));else if(response.status!==401)errorBox.textContent='暂时无法检查登录状态，请重试'}).catch(()=>{errorBox.textContent='网络不可用，请检查连接后重试'}).finally(()=>{checking=false;button.disabled=false});
