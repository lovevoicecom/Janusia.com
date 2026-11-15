JANUSIA v2.0 — BACKEND SETUP (10 minute, free)
================================================
Kyun chahiye: pehle sab data har browser ki localStorage mein tha, isliye Brave/Chrome alag-alag
dikhte the. Ab worker.js (Cloudflare Worker) asli IP dekhta hai aur sab kuch ek jagah rakhta hai.

1. dash.cloudflare.com par free account banao.
2. Workers & Pages > KV > "Create namespace" > naam: janusia-data
3. Workers & Pages > Create > Worker > naam: janusia-shield > Deploy > "Edit code"
   -> worker.js ka poora code paste karo > Deploy.
4. Worker > Settings > Bindings > Add > KV namespace
      Variable name: JANUSIA     Namespace: janusia-data
5. Worker > Settings > Variables and Secrets > Add (type = Secret)
      Name: ADMIN_PASSWORD   Value: wahi Owner password jo website mein daalte ho
   (optional) ALLOWED_ORIGIN = https://tumhari-site.com  (sirf tumhari site chale)
6. Worker ka URL copy karo (https://janusia-shield.XXXX.workers.dev)
7. index.html mein JanusiaConfig ke andar:
      BACKEND_URL: "https://janusia-shield.XXXX.workers.dev",
   Save karke GitHub/hosting par upload karo.
8. Owner tab kholo -> upar "● Backend Live" dikhna chahiye.

Free plan note: KV free limit (1,000 writes/din) chhoti site ke liye theek hai; zyada traffic ho to
Cloudflare Workers Paid ($5/mo) le lo.
