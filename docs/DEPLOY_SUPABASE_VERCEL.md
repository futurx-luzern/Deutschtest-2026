# Deployment (Vercel + Supabase) – Minimal Setup

## 1) Supabase vorbereiten
1. Neues Supabase-Projekt erstellen.
2. SQL Editor öffnen und `supabase/schema.sql` vollständig ausführen.
3. In `app_settings` den Admin-PIN ändern:
   ```sql
   update app_settings
   set admin_pin_hash = crypt('DEIN_ADMIN_PIN', gen_salt('bf'))
   where id = true;
   ```
4. Optional Plattform-Link setzen:
   ```sql
   update app_settings
   set platform_link = 'https://euer-test.vercel.app'
   where id = true;
   ```

## 2) Frontend konfigurieren
1. `public/js/supabase-config.example.js` nach `public/js/supabase-config.js` kopieren.
2. URL + Anon Key aus Supabase eintragen.

## 3) Lokal testen
Einfach statisch ausliefern, z. B. mit Python:
```bash
python -m http.server 5173 --directory public
```
Dann `http://localhost:5173` öffnen.

## 4) Vercel Deploy
1. Repo in Vercel importieren.
2. Root: Projektverzeichnis, Output: `public`.
3. Deploy starten.
4. Nach Deploy `app_settings.platform_link` auf die Vercel-URL aktualisieren.

## 5) Benutzerfluss
- Login: `index.html`
- Admin: `admin.html`
- Teilnehmer: `dashboard.html` → `test.html?assignment=<id>`

## 6) Wichtige Hinweise (MVP)
- Der MVP speichert `initial_pin` zur PDF-Ausgabe im Klartext. Für Produktion später ersetzen (z. B. Einmal-Token statt Klartext-PIN).
- `maybe_lock_inactive_assignments()` sollte regelmäßig laufen (z. B. pg_cron oder externer Trigger), damit 1h-Inaktivität automatisch sperrt.
- `admin_cleanup_expired_accounts()` regelmäßig ausführen, wenn Auto-Delete aktiv genutzt wird.
