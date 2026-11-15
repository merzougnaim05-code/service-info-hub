// مركز معطيات المؤسسة — Cloudflare Worker + Workers KV
// كل مؤسسة تُحدَّد بالرقم الميكانوغرافي: سجل مستقل لكل مؤسسة، لا تداخل.
// بلا توكنات بطلب صريح من المستخدم: الحفظ من البوابة ينشر تلقائيًا.
// الرقم الميكانوغرافي هو مفتاح السجل — من يعرفه يقرأه ويحدّثه.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Max-Age': '86400',
};

// تطبيع الرقم الميكانوغرافي: حروف/أرقام/شرطات/شرطة سفلية/نقاط، 3-32
function normalizeMecano(raw) {
  const s = String(raw || '').trim().toLowerCase().replace(/\s+/g, '-');
  if (!/^[a-z0-9._-]{3,32}$/.test(s)) return null;
  return s;
}

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', ...CORS },
});

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

    // قائمة المؤسسات المسجلة
    if (url.pathname === '/api/orgs' && request.method === 'GET') {
      const list = await env.INFO.list({ prefix: 'info:' });
      const orgs = [];
      for (const k of list.keys) {
        const mecano = k.name.slice('info:'.length);
        const raw = await env.INFO.get(k.name);
        let name = '';
        let updatedAt = null;
        try {
          const d = JSON.parse(raw);
          name = d.institution || '';
          updatedAt = d._updatedAt || null;
        } catch (e) { /* ignore */ }
        orgs.push({ mecano, institution: name, updatedAt });
      }
      return json({ ok: true, orgs });
    }

    const match = url.pathname.match(/^\/api\/info\/([^/]+)$/);
    if (!match) return json({ ok: false, error: 'مسار غير معروف' }, 404);
    const mecano = normalizeMecano(decodeURIComponent(match[1]));
    if (!mecano) return json({ ok: false, error: 'الرقم الميكانوغرافي غير صالح (حروف وأرقام وشرطات، 3-32)' }, 400);

    // القراءة
    if (request.method === 'GET') {
      const raw = await env.INFO.get('info:' + mecano);
      if (!raw) return json({ ok: false, error: 'لا يوجد سجل بهذا الرقم الميكانوغرافي' }, 404);
      let data;
      try { data = JSON.parse(raw); } catch (e) { return json({ ok: false, error: 'سجل تالف' }, 500); }
      return json({ ok: true, mecano, info: data, updatedAt: data._updatedAt || null });
    }

    // النشر: مفتوح بلا توكن — الحفظ من البوابة ينشر تلقائيًا
    if (request.method === 'PUT') {
      let body;
      try {
        body = await request.text();
        const parsed = JSON.parse(body);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw 0;
        if (body.length > 100 * 1024) return json({ ok: false, error: 'السجل أكبر من الحد (100KB)' }, 413);
        // طوابع مركزية: وقت آخر تحديث ومن رفع
        parsed._updatedAt = new Date().toISOString();
        parsed._by = url.searchParams.get('by') || '';
        await env.INFO.put('info:' + mecano, JSON.stringify(parsed));
        return json({ ok: true, mecano, updatedAt: parsed._updatedAt });
      } catch (e) {
        if (e && e.message) return json({ ok: false, error: e.message }, e.status || 400);
        return json({ ok: false, error: 'الجسم ليس JSON صالحًا' }, 400);
      }
    }

    return json({ ok: false, error: 'طريقة غير مدعومة' }, 405);
  },
};
