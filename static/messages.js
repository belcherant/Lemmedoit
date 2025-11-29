// Replace static/messages.js with this version.
// Key change: we fetch /api/me at startup to get the current user id,
// so there are no Jinja expressions embedded inside <script> tags.

(async function () {
  // Fetch current user id from server to avoid inline Jinja in JS.
  let CURRENT_USER_ID = null;
  try {
    const m = await fetch("/api/me", { credentials: "same-origin" });
    if (m.ok) {
      const j = await m.json();
      if (j.ok) CURRENT_USER_ID = j.id;
    }
  } catch (e) {
    console.warn("Failed to fetch current user id", e);
  }
  // Expose globally for backward compatibility with other scripts that expect window.CURRENT_USER_ID
  window.CURRENT_USER_ID = CURRENT_USER_ID;

  const convListEl = document.getElementById('conversationsList');
  const chatBody = document.getElementById('chatBody');
  const chatWith = document.getElementById('chatWith');
  const chatLastSeen = document.getElementById('chatLastSeen');
  const chatInput = document.getElementById('chatInput');
  const sendBtn = document.getElementById('sendMsgBtn');
  const convSearch = document.getElementById('convSearch');
  const newConvBtn = document.getElementById('newConvBtn');
  const deleteBtn = document.getElementById('deleteConvBtn');
  const reportBtn = document.getElementById('reportConvBtn');

  let conversations = [];
  let activeOther = null;
  let messages = [];
  let pollTimer = null;
  let selectedMessageId = null;

  function esc(s){ return String(s||'').replace(/[&<>"']/g, function(m){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[m]; }); }

  async function fetchConversations() {
    try {
      const res = await fetch('/api/messages/conversations', { credentials: "same-origin" });
      const j = await res.json();
      if (!j.ok) { convListEl.innerHTML = '<div class="no-conv">Unable to load conversations</div>'; return; }
      conversations = j.conversations || [];
      renderConversations();
    } catch (e) {
      convListEl.innerHTML = '<div class="no-conv">Error loading conversations</div>';
      console.error(e);
    }
  }

  function renderConversations(filter) {
    filter = (filter || '').toLowerCase();
    convListEl.innerHTML = '';
    const filtered = conversations.filter(c => !filter || (c.display||'').toLowerCase().includes(filter));
    if (filtered.length === 0) {
      convListEl.innerHTML = '<div class="no-conv">No conversations</div>';
      return;
    }
    filtered.forEach(c => {
      const div = document.createElement('div');
      div.className = 'conv-item';
      div.dataset.otherId = c.other_id;
      div.innerHTML = `<div style="flex:1"><div class="conv-title">${esc(c.display)}</div><div class="conv-snippet">${esc((c.last_message||'').substring(0,60))}</div></div>${c.unread_count ? '<div class="conv-unread">'+c.unread_count+'</div>' : ''}`;
      div.addEventListener('click', () => openConversation(c.other_id));
      convListEl.appendChild(div);
    });
  }

  async function openConversation(otherId) {
    activeOther = Number(otherId);
    selectedMessageId = null;
    const conv = conversations.find(c => Number(c.other_id) === Number(otherId)) || {};
    chatWith.textContent = conv.display || ('User ' + otherId);
    chatLastSeen.textContent = conv.last_at ? ('Last: ' + conv.last_at) : '';
    chatBody.innerHTML = '<div class="no-conv">Loading messages…</div>';
    messages = [];
    deleteBtn.style.display = 'inline-flex';
    reportBtn.style.display = 'inline-flex';
    await loadConversationMessages();
    Array.from(document.querySelectorAll('.conv-item')).forEach(el => el.classList.toggle('active', el.dataset.otherId == otherId));
    startPolling();
  }

  async function loadConversationMessages() {
    if (!activeOther) return;
    try {
      const res = await fetch('/api/messages/conversation/' + encodeURIComponent(activeOther), { credentials: "same-origin" });
      const j = await res.json();
      if (!j.ok) { chatBody.innerHTML = '<div class="no-conv">Failed to load messages</div>'; return; }
      messages = j.messages || [];
      renderMessages();
      await fetchConversations();
    } catch (e) {
      chatBody.innerHTML = '<div class="no-conv">Error loading messages</div>';
      console.error(e);
    }
  }

  function renderMessages() {
    chatBody.innerHTML = '';
    selectedMessageId = null;
    if (!messages || messages.length === 0) {
      chatBody.innerHTML = '<div class="no-conv">No messages yet — say hello!</div>';
      return;
    }
    messages.forEach(m => {
      const div = document.createElement('div');
      const isMe = Number(m.sender_id) === Number(window.CURRENT_USER_ID);
      div.className = 'msg ' + (isMe ? 'me' : 'they');
      div.dataset.msgId = m.id || '';
      div.innerHTML = `<div>${esc(m.body)}</div><div class="small-muted" style="font-size:11px; margin-top:6px;">${esc((m.created_at||'').slice(0,19).replace('T',' '))}</div>`;
      div.addEventListener('click', function () {
        if (selectedMessageId && selectedMessageId == div.dataset.msgId) {
          selectedMessageId = null;
          div.classList.remove('selected');
        } else {
          Array.from(chatBody.querySelectorAll('.msg.selected')).forEach(x => x.classList.remove('selected'));
          selectedMessageId = div.dataset.msgId;
          div.classList.add('selected');
        }
      });
      chatBody.appendChild(div);
    });
    chatBody.scrollTop = chatBody.scrollHeight + 200;
  }

  async function sendMessage() {
    const body = (chatInput.value || '').trim();
    if (!body || !activeOther) return;
    sendBtn.disabled = true;
    try {
      const res = await fetch('/api/messages/send', {
        method: 'POST',
        credentials: "same-origin",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient_id: activeOther, body: body })
      });
      const j = await res.json();
      if (!j.ok) {
        alert(j.error || 'Failed to send message');
      } else {
        chatInput.value = '';
        messages.push(j.message);
        renderMessages();
        fetchConversations();
      }
    } catch (e) {
      console.error(e);
      alert('Error sending message');
    } finally {
      sendBtn.disabled = false;
    }
  }

  function startPolling() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
      if (!activeOther) return;
      try {
        const res = await fetch('/api/messages/conversation/' + encodeURIComponent(activeOther), { credentials: "same-origin" });
        const j = await res.json();
        if (j.ok) {
          messages = j.messages || [];
          renderMessages();
          fetchConversations();
        }
      } catch (e) {
        console.error('poll error', e);
      }
    }, 4000);
  }

  async function lookupByEmail(email) {
    if (!email) return null;
    try {
      const res = await fetch('/api/users/lookup?email=' + encodeURIComponent(email), { credentials: "same-origin" });
      if (!res.ok) return null;
      const j = await res.json();
      return j.ok ? j.user : null;
    } catch (e) {
      console.error('lookup error', e);
      return null;
    }
  }

  newConvBtn.addEventListener('click', async function () {
    const email = (prompt('Enter the email of the person you want to message:') || '').trim().toLowerCase();
    if (!email) return;
    const user = await lookupByEmail(email);
    if (!user) {
      alert('No account found with that email.');
      return;
    }
    activeOther = user.id;
    chatWith.textContent = user.display || ('User ' + user.id);
    chatBody.innerHTML = '<div class="no-conv">No messages yet — send the first message</div>';
    deleteBtn.style.display = 'inline-flex';
    reportBtn.style.display = 'inline-flex';
    startPolling();
    fetchConversations();
  });

  deleteBtn.addEventListener('click', async function () {
    if (!activeOther) return;
    if (!confirm('Delete this conversation for everyone? This is irreversible.')) return;
    try {
      const res = await fetch('/api/messages/delete_conversation', {
        method: 'POST',
        credentials: "same-origin",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ other_id: activeOther })
      });
      const j = await res.json();
      if (j.ok) {
        messages = [];
        renderMessages();
        fetchConversations();
        alert('Conversation deleted.');
      } else {
        alert(j.error || 'Failed to delete conversation');
      }
    } catch (e) {
      console.error(e);
      alert('Error deleting conversation');
    }
  });

  reportBtn.addEventListener('click', async function () {
    if (!activeOther) return;
    const reason = (prompt('Why are you reporting this conversation? Please provide details:') || '').trim();
    if (!reason) return;
    const payload = { other_id: activeOther, reason: reason };
    if (selectedMessageId) payload.message_id = Number(selectedMessageId);
    try {
      const res = await fetch('/api/messages/report', {
        method: 'POST',
        credentials: "same-origin",
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const j = await res.json();
      if (j.ok) {
        alert('Report submitted. Our admins will review it.');
        selectedMessageId = null;
        Array.from(chatBody.querySelectorAll('.msg.selected')).forEach(x => x.classList.remove('selected'));
      } else {
        alert(j.error || 'Failed to submit report');
      }
    } catch (e) {
      console.error(e);
      alert('Error submitting report');
    }
  });

  sendBtn.addEventListener('click', sendMessage);
  chatInput.addEventListener('keydown', function (e) { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { sendMessage(); } });
  convSearch.addEventListener('input', function () { renderConversations(this.value); });

  async function openFromUrl() {
    const params = new URLSearchParams(window.location.search);
    if (params.has('other_id')) {
      const id = params.get('other_id');
      await fetchConversations();
      openConversation(id);
    } else if (params.has('other_email')) {
      const email = (params.get('other_email') || '').trim().toLowerCase();
      const user = await lookupByEmail(email);
      await fetchConversations();
      if (user) openConversation(user.id);
      else chatBody.innerHTML = '<div class="no-conv">No user found for that email.</div>';
    } else {
      await fetchConversations();
    }
  }

  openFromUrl();

  window.__messages_ui = { fetchConversations, openConversation, loadConversationMessages };
})();