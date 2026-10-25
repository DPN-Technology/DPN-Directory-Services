# Local developer quickstart

Requires Python 3.11+, Node 20.19+ (or 22.12+) and npm.

## Run the API (demo)

From backend/:

1. Create a Python virtual environment and activate it.
2. Install: python -m pip install -e ".[dev]"
3. Generate a new token with: python -c "import secrets; print(secrets.token_urlsafe(48))"
4. Set DPN_DS_API_TOKEN to the generated value and DPN_DS_MODE=demo.
5. Run: uvicorn dpn_ds.app:app --host 127.0.0.1 --port 8000

On Linux you can configure with:
~~~bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
export DPN_DS_MODE=demo
export DPN_DS_API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
uvicorn dpn_ds.app:app --host 127.0.0.1 --port 8000
~~~

The generated token is printed nowhere by the service; to use the console, obtain it from the environment where you set it. Do not commit it.

## Run the console

From a second terminal:

~~~bash
cd frontend
npm install
npm run dev
~~~

Open http://127.0.0.1:5173 and enter your operator API token. Vite forwards /api requests to 127.0.0.1:8000. The token is held only in the active page's memory and is cleared on reload or disconnect.

## Testing

~~~bash
cd backend && python -m pytest -q && ruff check .
cd ../frontend && npm run build
~~~

## Samba mode

Set DPN_DS_MODE=samba and configure DPN_DS_REALM and DPN_DS_CONTROLLER. This adapter calls local samba-tool. It will report an error if the tool is absent or the runtime identity lacks sufficient directory permissions. There is no automatic fallback to fake data.

Until the privileged adapter and authentication architecture are hardened, use Samba mode only in a trusted isolated lab; never expose it publicly.
