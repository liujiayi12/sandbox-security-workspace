# ASGuard

Independent frontend for two local security services:

- Skill dynamic detection: proxied from `/skill-api` to `http://127.0.0.1:8787`
- Agent analysis: proxied from `/agent-api` to `http://127.0.0.1:8000`

## Development

```powershell
npm.cmd install
npm.cmd run dev
```

Open `http://127.0.0.1:5174`.

## Build

```powershell
npm.cmd run build
```
