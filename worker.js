// worker.js
// 极简实现，确保部署成功

// 管理员凭证
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'xiyue777';
const BAN_MESSAGE = '您的账号已被管理员封禁,请联系 linyi8100@gmail.com 解封';

// SHA-256 简化实现（仅用于 JWT 签名验证）
function simpleSha256(str) {
  // 这是一个简化版，仅用于演示。实际生产环境应使用 crypto.subtle
  let hash = 0, i, chr;
  for (i = 0; i < str.length; i++) {
    chr = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0; // Convert to 32bit integer
  }
  return hash.toString(16);
}

// 响应帮助函数
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
    }
  });
}

// 处理 OPTIONS 预检请求
function handleOptions() {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization'
    }
  });
}

// 初始化管理员
async function initAdmin(env) {
  const adminKey = `users/${ADMIN_USERNAME}`;
  const existing = await env.BLOG_KV.get(adminKey);
  if (!existing) {
    // 使用简单哈希代替 PBKDF2（简化部署）
    const passwordHash = simpleSha256(ADMIN_PASSWORD);
    
    await env.BLOG_KV.put(adminKey, JSON.stringify({
      passwordHash,
      avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=admin',
      banned: false,
      role: 'admin',
      createdAt: new Date().toISOString()
    }));
  }
}

// 验证用户登录
async function verifyUser(env, username, password) {
  const userKey = `users/${username}`;
  const userData = await env.BLOG_KV.get(userKey);
  
  if (!userData) return null;
  
  const user = JSON.parse(userData);
  const expectedHash = simpleSha256(password);
  
  if (user.passwordHash === expectedHash && !user.banned) {
    return {
      username: user.username,
      role: user.role,
      avatar: user.avatar
    };
  }
  
  return null;
}

// 验证 JWT 令牌
function verifyToken(token, secret) {
  try {
    const [header, payload, signature] = token.split('.');
    // 简单验证（实际生产环境应更严格）
    return signature === simpleSha256(header + payload + secret);
  } catch {
    return false;
  }
}

// 解码令牌
function decodeToken(token) {
  try {
    const payload = token.split('.')[1];
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

// 检查权限
async function checkPermission(env, request, requiredRole = null) {
  const token = request.headers.get('Authorization')?.split(' ')[1];
  if (!token) return { valid: false, error: '未授权' };
  
  // 验证令牌
  if (!verifyToken(token, env.SECRET_KEY)) {
    return { valid: false, error: '无效令牌' };
  }
  
  // 解码令牌
  const payload = decodeToken(token);
  if (!payload || !payload.username) {
    return { valid: false, error: '无效令牌' };
  }
  
  // 获取用户信息
  const user = await env.BLOG_KV.get(`users/${payload.username}`);
  if (!user) {
    return { valid: false, error: '用户不存在' };
  }
  
  const userData = JSON.parse(user);
  if (userData.banned) {
    return { valid: false, error: BAN_MESSAGE };
  }
  
  // 检查角色要求
  if (requiredRole === 'admin' && userData.role !== 'admin') {
    return { valid: false, error: '需要管理员权限' };
  }
  
  return { 
    valid: true, 
    user: {
      username: payload.username,
      role: userData.role,
      avatar: userData.avatar
    }
  };
}

// 主处理函数
export default {
  async fetch(request, env) {
    // 初始化管理员
    await initAdmin(env);
    
    const url = new URL(request.url);
    const pathname = url.pathname;
    
    // 处理 OPTIONS 预检
    if (request.method === 'OPTIONS') {
      return handleOptions();
    }
    
    // 处理根路径 - 返回前端 HTML
    if (pathname === '/') {
      return new Response(indexHTML, {
        headers: { 
          'Content-Type': 'text/html',
          'Access-Control-Allow-Origin': '*'
        }
      });
    }
    
    // API 路由
    if (pathname.startsWith('/api/')) {
      try {
        // 用户注册
        if (pathname === '/api/register' && request.method === 'POST') {
          const { username, password, avatar } = await request.json();
          
          // 检查用户名是否已存在
          const existing = await env.BLOG_KV.get(`users/${username}`);
          if (existing) {
            return jsonResponse({ error: '用户名已存在' }, 400);
          }
          
          // 创建新用户
          const passwordHash = simpleSha256(password);
          await env.BLOG_KV.put(`users/${username}`, JSON.stringify({
            username,
            passwordHash,
            avatar: avatar || 'https://api.dicebear.com/7.x/avataaars/svg?seed=default',
            banned: false,
            role: 'user',
            createdAt: new Date().toISOString()
          }));
          
          return jsonResponse({ success: true });
        }
        
        // 用户登录
        if (pathname === '/api/login' && request.method === 'POST') {
          const { username, password } = await request.json();
          
          // 验证用户
          const user = await verifyUser(env, username, password);
          if (!user) {
            return jsonResponse({ error: '用户名或密码错误' }, 401);
          }
          
          // 生成简单令牌
          const payload = {
            username: user.username,
            role: user.role,
            exp: Date.now() + 86400000 // 24小时
          };
          
          const header = btoa(JSON.stringify({ alg: 'HS256' }));
          const payloadStr = btoa(JSON.stringify(payload));
          const signature = simpleSha256(header + payloadStr + env.SECRET_KEY);
          
          return jsonResponse({
            token: `${header}.${payloadStr}.${signature}`,
            username: user.username,
            role: user.role,
            avatar: user.avatar
          });
        }
        
        // 获取所有帖子
        if (pathname === '/api/posts' && request.method === 'GET') {
          const list = await env.BLOG_KV.list({ prefix: 'posts/' });
          const posts = [];
          
          for (const key of list.keys) {
            const post = await env.BLOG_KV.get(key.name, 'json');
            if (post) posts.push(post);
          }
          
          // 按时间排序（最新在前）
          posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
          
          return jsonResponse(posts);
        }
        
        // 发布新帖子
        if (pathname === '/api/posts' && request.method === 'POST') {
          const { valid, error, user } = await checkPermission(env, request);
          if (!valid) return jsonResponse({ error }, 403);
          
          const { title, content, type } = await request.json();
          const postId = crypto.randomUUID();
          
          await env.BLOG_KV.put(`posts/${postId}`, JSON.stringify({
            id: postId,
            title,
            content,
            type,
            author: user.username,
            avatar: user.avatar,
            createdAt: new Date().toISOString()
          }));
          
          return jsonResponse({ postId });
        }
        
        // 删除帖子
        if (pathname.startsWith('/api/posts/') && request.method === 'DELETE') {
          const { valid, error, user } = await checkPermission(env, request, 'admin');
          if (!valid) return jsonResponse({ error }, 403);
          
          const postId = pathname.split('/').pop();
          await env.BLOG_KV.delete(`posts/${postId}`);
          
          // 删除相关评论
          const commentKeys = await env.BLOG_KV.list({ prefix: `comments/${postId}/` });
          if (commentKeys.keys.length > 0) {
            await Promise.all(commentKeys.keys.map(k => env.BLOG_KV.delete(k.name)));
          }
          
          return jsonResponse({ success: true });
        }
        
        // 发布评论
        if (pathname.startsWith('/api/posts/') && pathname.endsWith('/comments') && request.method === 'POST') {
          const { valid, error, user } = await checkPermission(env, request);
          if (!valid) return jsonResponse({ error }, 403);
          
          const postId = pathname.split('/')[3];
          const { content } = await request.json();
          const commentId = crypto.randomUUID();
          
          await env.BLOG_KV.put(`comments/${postId}/${commentId}`, JSON.stringify({
            id: commentId,
            content,
            author: user.username,
            avatar: user.avatar,
            createdAt: new Date().toISOString()
          }));
          
          return jsonResponse({ commentId });
        }
        
        // 获取帖子评论
        if (pathname.startsWith('/api/posts/') && pathname.endsWith('/comments') && request.method === 'GET') {
          const postId = pathname.split('/')[3];
          const list = await env.BLOG_KV.list({ prefix: `comments/${postId}/` });
          const comments = [];
          
          for (const key of list.keys) {
            const comment = await env.BLOG_KV.get(key.name, 'json');
            if (comment) comments.push(comment);
          }
          
          // 按时间排序（最新在前）
          comments.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
          
          return jsonResponse(comments);
        }
        
        // 封禁用户（仅管理员）
        if (pathname === '/api/ban' && request.method === 'POST') {
          const { valid, error, user } = await checkPermission(env, request, 'admin');
          if (!valid) return jsonResponse({ error }, 403);
          
          const { username } = await request.json();
          if (username === 'admin') {
            return jsonResponse({ error: '不能封禁管理员' }, 400);
          }
          
          const userKey = `users/${username}`;
          const userData = await env.BLOG_KV.get(userKey);
          
          if (!userData) {
            return jsonResponse({ error: '用户不存在' }, 404);
          }
          
          const userObj = JSON.parse(userData);
          userObj.banned = true;
          
          await env.BLOG_KV.put(userKey, JSON.stringify(userObj));
          return jsonResponse({ success: true });
        }
        
        // 解封用户（仅管理员）
        if (pathname === '/api/unban' && request.method === 'POST') {
          const { valid, error, user } = await checkPermission(env, request, 'admin');
          if (!valid) return jsonResponse({ error }, 403);
          
          const { username } = await request.json();
          const userKey = `users/${username}`;
          const userData = await env.BLOG_KV.get(userKey);
          
          if (!userData) {
            return jsonResponse({ error: '用户不存在' }, 404);
          }
          
          const userObj = JSON.parse(userData);
          userObj.banned = false;
          
          await env.BLOG_KV.put(userKey, JSON.stringify(userObj));
          return jsonResponse({ success: true });
        }
        
        return jsonResponse({ error: 'API 未找到' }, 404);
      } catch (error) {
        console.error('API Error:', error);
        return jsonResponse({ 
          error: '服务器错误',
          message: error.message 
        }, 500);
      }
    }
    
    // 404 处理
    return new Response('Not Found', { 
      status: 404,
      headers: { 'Access-Control-Allow-Origin': '*' }
    });
  }
};

// 前端 HTML（简化版，确保无语法错误）
const indexHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>渐变贴吧</title>
  <style>
    :root {
      --primary: #6a11cb;
      --secondary: #2575fc;
      --blur: 12px;
    }
    
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
      transition: background 0.5s ease;
    }
    
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      min-height: 100vh;
      padding: 20px;
      color: #333;
      overflow-x: hidden;
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    
    header {
      text-align: center;
      padding: 30px 0;
      margin-bottom: 30px;
    }
    
    h1 {
      font-size: 3.5rem;
      background: linear-gradient(to right, #fff, #e0e0e0);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      text-shadow: 0 2px 10px rgba(0,0,0,0.2);
      margin-bottom: 10px;
    }
    
    .subtitle {
      color: rgba(255, 255, 255, 0.8);
      font-size: 1.2rem;
      max-width: 600px;
      margin: 0 auto;
    }
    
    .card {
      background: rgba(255, 255, 255, 0.85);
      border-radius: 20px;
      backdrop-filter: blur(var(--blur));
      -webkit-backdrop-filter: blur(var(--blur));
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
      padding: 25px;
      margin-bottom: 30px;
      overflow: hidden;
    }
    
    .card h2 {
      color: var(--primary);
      margin-bottom: 20px;
      padding-bottom: 10px;
      border-bottom: 2px solid rgba(106, 17, 203, 0.2);
    }
    
    .form-group {
      margin-bottom: 20px;
    }
    
    label {
      display: block;
      margin-bottom: 8px;
      font-weight: 600;
      color: var(--primary);
    }
    
    input, textarea, select {
      width: 100%;
      padding: 12px 15px;
      border: 2px solid #e0e0e0;
      border-radius: 10px;
      font-size: 16px;
      transition: all 0.3s;
    }
    
    input:focus, textarea:focus, select:focus {
      outline: none;
      border-color: var(--secondary);
      box-shadow: 0 0 0 3px rgba(37, 117, 252, 0.2);
    }
    
    button {
      background: linear-gradient(to right, var(--primary), var(--secondary));
      color: white;
      border: none;
      padding: 12px 25px;
      border-radius: 50px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
      box-shadow: 0 4px 15px rgba(106, 17, 203, 0.3);
    }
    
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 7px 20px rgba(106, 17, 203, 0.4);
    }
    
    .post {
      background: white;
      border-radius: 15px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
      border-left: 4px solid var(--secondary);
    }
    
    .post-header {
      display: flex;
      align-items: center;
      margin-bottom: 15px;
    }
    
    .avatar {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      object-fit: cover;
      margin-right: 12px;
      border: 2px solid var(--secondary);
    }
    
    .author {
      font-weight: 600;
      color: var(--primary);
    }
    
    .post-title {
      font-size: 1.5rem;
      margin: 10px 0;
      color: #2c3e50;
    }
    
    .post-content {
      line-height: 1.6;
      color: #444;
      margin-bottom: 15px;
    }
    
    .comment {
      background: #f8f9fa;
      padding: 12px 15px;
      border-radius: 10px;
      margin-top: 10px;
      border-left: 3px solid var(--primary);
    }
    
    .comment-header {
      display: flex;
      align-items: center;
      margin-bottom: 5px;
    }
    
    .comment-author {
      font-weight: 600;
      color: var(--secondary);
      margin-right: 8px;
    }
    
    .comment-time {
      color: #777;
      font-size: 0.85rem;
    }
    
    .controls {
      display: flex;
      gap: 10px;
      margin-top: 15px;
    }
    
    .btn-delete {
      background: #ff4757;
      padding: 6px 12px;
      font-size: 0.9rem;
    }
    
    .auth-section {
      display: flex;
      gap: 15px;
      margin-top: 10px;
    }
    
    .user-info {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    
    .error {
      color: #ff4757;
      background: #ffeaa7;
      padding: 10px;
      border-radius: 8px;
      margin: 15px 0;
      display: none;
    }
    
    .tabs {
      display: flex;
      margin-bottom: 20px;
      border-bottom: 1px solid #e0e0e0;
    }
    
    .tab {
      padding: 12px 25px;
      cursor: pointer;
      font-weight: 600;
      color: #777;
    }
    
    .tab.active {
      color: var(--primary);
      border-bottom: 3px solid var(--primary);
    }
    
    .tab-content {
      display: none;
    }
    
    .tab-content.active {
      display: block;
    }
    
    @media (max-width: 768px) {
      h1 {
        font-size: 2.5rem;
      }
      
      .card {
        padding: 20px 15px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>渐变贴吧</h1>
      <p class="subtitle">一个丝滑流畅、实时模糊渐变的博客社区</p>
    </header>

    <div class="auth-section" id="authSection">
      <!-- 动态生成登录/注册/用户信息 -->
    </div>

    <div class="tabs">
      <div class="tab active" data-tab="posts">全部帖子</div>
      <div class="tab" data-tab="create">发帖</div>
    </div>

    <div id="postsTab" class="tab-content active">
      <div class="card">
        <h2>最新帖子</h2>
        <div id="postsContainer">
          <!-- 帖子将动态加载到这里 -->
        </div>
      </div>
    </div>

    <div id="createTab" class="tab-content">
      <div class="card">
        <h2>发布新帖</h2>
        <div class="form-group">
          <label for="postTitle">标题</label>
          <input type="text" id="postTitle" placeholder="输入帖子标题">
        </div>
        <div class="form-group">
          <label for="postType">类型</label>
          <select id="postType">
            <option value="text">纯文字</option>
            <option value="图文">图文</option>
          </select>
        </div>
        <div class="form-group">
          <label for="postContent">内容</label>
          <textarea id="postContent" rows="6" placeholder="分享你的想法..."></textarea>
        </div>
        <button id="submitPost">发布帖子</button>
        <div class="error" id="postError"></div>
      </div>
    </div>

    <div id="registerModal" class="card" style="display:none;">
      <h2>注册账号</h2>
      <div class="form-group">
        <label for="regUsername">用户名</label>
        <input type="text" id="regUsername" placeholder="输入用户名">
      </div>
      <div class="form-group">
        <label for="regPassword">密码</label>
        <input type="password" id="regPassword" placeholder="输入密码">
      </div>
      <div class="form-group">
        <label for="regAvatar">头像直链 (可选)</label>
        <input type="url" id="regAvatar" placeholder="https://example.com/avatar.jpg">
      </div>
      <button id="registerBtn">注册账号</button>
      <div class="error" id="regError"></div>
      <p>已有账号? <a href="#" id="showLogin">去登录</a></p>
    </div>

    <div id="loginModal" class="card">
      <h2>登录账号</h2>
      <div class="form-group">
        <label for="loginUsername">用户名</label>
        <input type="text" id="loginUsername" placeholder="输入用户名">
      </div>
      <div class="form-group">
        <label for="loginPassword">密码</label>
        <input type="password" id="loginPassword" placeholder="输入密码">
      </div>
      <button id="loginBtn">登录</button>
      <div class="error" id="loginError"></div>
      <p>没有账号? <a href="#" id="showRegister">去注册</a></p>
    </div>
  </div>

  <script>
    // 全局状态
    const state = {
      token: localStorage.getItem('token'),
      username: localStorage.getItem('username'),
      role: localStorage.getItem('role'),
      avatar: localStorage.getItem('avatar')
    };

    // DOM 元素
    const elements = {
      authSection: document.getElementById('authSection'),
      postsContainer: document.getElementById('postsContainer'),
      postTitle: document.getElementById('postTitle'),
      postType: document.getElementById('postType'),
      postContent: document.getElementById('postContent'),
      submitPost: document.getElementById('submitPost'),
      postError: document.getElementById('postError'),
      loginUsername: document.getElementById('loginUsername'),
      loginPassword: document.getElementById('loginPassword'),
      loginBtn: document.getElementById('loginBtn'),
      loginError: document.getElementById('loginError'),
      regUsername: document.getElementById('regUsername'),
      regPassword: document.getElementById('regPassword'),
      regAvatar: document.getElementById('regAvatar'),
      registerBtn: document.getElementById('registerBtn'),
      regError: document.getElementById('regError'),
      showRegister: document.getElementById('showRegister'),
      showLogin: document.getElementById('showLogin'),
      registerModal: document.getElementById('registerModal'),
      loginModal: document.getElementById('loginModal'),
      tabs: document.querySelectorAll('.tab'),
      tabContents: document.querySelectorAll('.tab-content')
    };

    // 显示错误
    function showError(element, message) {
      element.textContent = message;
      element.style.display = 'block';
    }
    
    function clearError(element) {
      element.textContent = '';
      element.style.display = 'none';
    }

    // 初始化
    function init() {
      setupEventListeners();
      updateAuthUI();
      loadPosts();
      
      // 渐变动画
      setInterval(function() {
        var hue = Math.floor(Math.random() * 360);
        document.documentElement.style.setProperty('--primary', 'hsl(' + hue + ', 70%, 50%)');
        document.documentElement.style.setProperty('--secondary', 'hsl(' + ((hue + 60) % 360) + ', 70%, 50%)');
      }, 5000);
    }

    // 设置事件监听
    function setupEventListeners() {
      // 切换标签
      elements.tabs.forEach(function(tab) {
        tab.addEventListener('click', function() {
          elements.tabs.forEach(function(t) {
            t.classList.remove('active');
          });
          tab.classList.add('active');
          
          var tabName = tab.getAttribute('data-tab');
          elements.tabContents.forEach(function(content) {
            content.classList.remove('active');
            if (content.id === tabName + 'Tab') {
              content.classList.add('active');
            }
          });
        });
      });

      // 登录
      elements.loginBtn.addEventListener('click', function() {
        var username = elements.loginUsername.value;
        var password = elements.loginPassword.value;
        
        if (!username || !password) {
          showError(elements.loginError, '请填写完整信息');
          return;
        }
        
        fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: username, password: password })
        })
        .then(function(response) {
          return response.json();
        })
        .then(function(data) {
          if (data.token) {
            state.token = data.token;
            state.username = data.username;
            state.role = data.role;
            state.avatar = data.avatar;
            
            localStorage.setItem('token', data.token);
            localStorage.setItem('username', data.username);
            localStorage.setItem('role', data.role);
            localStorage.setItem('avatar', data.avatar);
            
            updateAuthUI();
            clearError(elements.loginError);
            elements.loginUsername.value = '';
            elements.loginPassword.value = '';
          } else {
            showError(elements.loginError, data.error || '登录失败');
          }
        })
        .catch(function(error) {
          console.error('Login error:', error);
          showError(elements.loginError, '网络错误，请重试');
        });
      });

      // 注册
      elements.registerBtn.addEventListener('click', function() {
        var username = elements.regUsername.value;
        var password = elements.regPassword.value;
        var avatar = elements.regAvatar.value;
        
        if (!username || !password) {
          showError(elements.regError, '请填写完整信息');
          return;
        }
        
        fetch('/api/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            username: username, 
            password: password,
            avatar: avatar 
          })
        })
        .then(function(response) {
          return response.json();
        })
        .then(function(data) {
          if (data.success) {
            alert('注册成功！请登录');
            elements.regUsername.value = '';
            elements.regPassword.value = '';
            elements.regAvatar.value = '';
            clearError(elements.regError);
            showLoginModal();
          } else {
            showError(elements.regError, data.error || '注册失败');
          }
        })
        .catch(function(error) {
          console.error('Register error:', error);
          showError(elements.regError, '网络错误，请重试');
        });
      });

      // 发布帖子
      elements.submitPost.addEventListener('click', function() {
        var title = elements.postTitle.value;
        var content = elements.postContent.value;
        var type = elements.postType.value;
        
        if (!title || !content) {
          showError(elements.postError, '标题和内容不能为空');
          return;
        }
        
        fetch('/api/posts', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + state.token
          },
          body: JSON.stringify({ 
            title: title, 
            content: content, 
            type: type 
          })
        })
        .then(function(response) {
          return response.json();
        })
        .then(function(data) {
          if (data.postId) {
            elements.postTitle.value = '';
            elements.postContent.value = '';
            clearError(elements.postError);
            loadPosts();
          } else {
            showError(elements.postError, data.error || '发帖失败');
          }
        })
        .catch(function(error) {
          console.error('Post error:', error);
          showError(elements.postError, '网络错误，请重试');
        });
      });

      // 切换注册/登录模态框
      elements.showRegister.addEventListener('click', function(e) {
        e.preventDefault();
        showRegisterModal();
      });
      
      elements.showLogin.addEventListener('click', function(e) {
        e.preventDefault();
        showLoginModal();
      });
    }

    // 加载帖子
    function loadPosts() {
      fetch('/api/posts')
        .then(function(response) {
          return response.json();
        })
        .then(function(posts) {
          var html = '';
          for (var i = 0; i < posts.length; i++) {
            var post = posts[i];
            html += '<div class="post">' +
              '<div class="post-header">' +
                '<img src="' + (post.avatar || 'https://api.dicebear.com/7.x/avataaars/svg?seed=default') + '" ' +
                     'alt="' + post.author + '" class="avatar">' +
                '<div>' +
                  '<div class="author">' + post.author + '</div>' +
                  '<div class="post-time">' + new Date(post.createdAt).toLocaleString() + '</div>' +
                '</div>' +
              '</div>' +
              '<h3 class="post-title">' + post.title + '</h3>' +
              '<div class="post-content">' + post.content + '</div>';
            
            // 添加删除按钮（仅管理员和作者可见）
            if (state.username && (state.role === 'admin' || state.username === post.author)) {
              html += '<div class="controls">' +
                        '<button class="btn-delete" data-post-id="' + post.id + '">删除</button>' +
                      '</div>';
            }
            
            html += '<div class="comments">' +
                      '<h4>评论</h4>' +
                      '<div class="form-group" style="margin-top: 15px;">' +
                        '<textarea class="comment-input" placeholder="发表评论..." ' +
                                  'data-post-id="' + post.id + '" rows="2"></textarea>' +
                        '<button class="submit-comment" data-post-id="' + post.id + '">评论</button>' +
                      '</div>' +
                    '</div>' +
                  '</div>';
          }
          
          elements.postsContainer.innerHTML = html || '<p>还没有帖子，快来发布第一条吧！</p>';
          
          // 添加删除事件
          var deleteButtons = document.querySelectorAll('.btn-delete');
          for (var i = 0; i < deleteButtons.length; i++) {
            deleteButtons[i].addEventListener('click', function() {
              var postId = this.getAttribute('data-post-id');
              
              if (!confirm('确定要删除这个帖子吗？')) return;
              
              fetch('/api/posts/' + postId, {
                method: 'DELETE',
                headers: { 'Authorization': 'Bearer ' + state.token }
              })
              .then(function(response) {
                if (response.ok) {
                  loadPosts();
                } else {
                  response.json().then(function(data) {
                    alert(data.error || '删除失败');
                  });
                }
              });
            });
          }
          
          // 添加评论事件
          var commentButtons = document.querySelectorAll('.submit-comment');
          for (var i = 0; i < commentButtons.length; i++) {
            commentButtons[i].addEventListener('click', function() {
              var postId = this.getAttribute('data-post-id');
              var textarea = document.querySelector('.comment-input[data-post-id="' + postId + '"]');
              var content = textarea.value;
              
              if (!content) {
                alert('评论内容不能为空');
                return;
              }
              
              fetch('/api/posts/' + postId + '/comments', {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': 'Bearer ' + state.token
                },
                body: JSON.stringify({ content: content })
              })
              .then(function(response) {
                if (response.ok) {
                  textarea.value = '';
                  loadPosts();
                } else {
                  response.json().then(function(data) {
                    alert(data.error || '评论失败');
                  });
                }
              });
            });
          }
        })
        .catch(function(error) {
          console.error('Load posts error:', error);
          elements.postsContainer.innerHTML = '<p>加载帖子失败，请刷新重试</p>';
        });
    }

    // 更新认证UI
    function updateAuthUI() {
      var html = '';
      
      if (state.token) {
        html = '<div class="user-info">' +
          '<img src="' + state.avatar + '" alt="' + state.username + '" class="avatar" style="width:40px;height:40px;">' +
          '<div>' +
            '<div>' + state.username + ' ' + (state.role === 'admin' ? '(管理员)' : '') + '</div>' +
            '<button id="logoutBtn" style="margin-top:5px;padding:3px 10px;font-size:0.9rem;">退出</button>' +
          '</div>' +
        '</div>';
      } else {
        html = '<button id="loginBtnUI">登录</button>' +
               '<button id="registerBtnUI">注册</button>';
      }
      
      elements.authSection.innerHTML = html;
      
      if (!state.token) {
        elements.loginModal.style.display = 'block';
        elements.registerModal.style.display = 'none';
      } else {
        document.getElementById('logoutBtn').addEventListener('click', logout);
      }
      
      var loginBtnUI = document.getElementById('loginBtnUI');
      if (loginBtnUI) {
        loginBtnUI.addEventListener('click', showLoginModal);
      }
      
      var registerBtnUI = document.getElementById('registerBtnUI');
      if (registerBtnUI) {
        registerBtnUI.addEventListener('click', showRegisterModal);
      }
    }

    // 显示模态框
    function showLoginModal() {
      elements.loginModal.style.display = 'block';
      elements.registerModal.style.display = 'none';
    }
    
    function showRegisterModal() {
      elements.loginModal.style.display = 'none';
      elements.registerModal.style.display = 'block';
    }

    // 退出登录
    function logout() {
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      localStorage.removeItem('role');
      localStorage.removeItem('avatar');
      
      state.token = null;
      state.username = null;
      state.role = null;
      state.avatar = null;
      
      updateAuthUI();
      loadPosts();
    }

    // 初始化应用
    document.addEventListener('DOMContentLoaded', init);
  </script>
</body>
</html>`;