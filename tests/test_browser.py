"""Optional real-browser flow. Install requirements-browser.txt and Chromium first."""
import threading

import pytest
from werkzeug.serving import make_server

from conftest import PASSWORD, code

playwright = pytest.importorskip("playwright.sync_api", reason="Optional browser dependencies not installed")


def test_real_browser_enrollment_and_privacy(app, tmp_path):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    errors, payloads = [], []
    try:
        with playwright.sync_playwright() as runner:
            browser = runner.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda req: payloads.append(req.post_data_json)
                    if req.url.endswith("/api/telemetry") else None)
            page.goto(f"http://127.0.0.1:{server.server_port}")
            page.get_by_role("link", name="Create a local account").click()
            page.get_by_label("Account name", exact=True).fill("alice")
            page.get_by_label("Password or passphrase").fill(PASSWORD)
            page.get_by_role("checkbox").check()
            page.get_by_role("button", name="Create account").click()
            page.wait_for_url("**/setup")
            assert page.locator(".qr svg").count() == 1
            page.get_by_label("Current six-digit code").fill(code(app))
            page.get_by_role("button", name="Confirm authenticator").click()
            assert page.locator(".codes li").count() == 5
            page.get_by_role("link", name="I saved my codes").click()
            page.wait_for_url("**/dashboard")
            page.get_by_role("link", name="Collect an enrollment round").click()
            page.get_by_role("link", name="Verify to start a round").click()
            page.get_by_label("Password", exact=True).fill(PASSWORD)
            page.get_by_label("Authenticator or unused recovery code").fill(code(app))
            page.get_by_role("button", name="Verify", exact=True).click()
            page.get_by_role("button", name="Start verified round").click()
            page.locator("#collect-toggle").check()
            area = page.locator("#typing-area")
            # Pasting text must not create timing observations.
            area.fill("PRIVATE_TEXT_MUST_NOT_LEAVE_THE_BROWSER")
            assert not payloads
            area.focus()
            for char in "thequickbrownfoxjumpsoverthelazydog":
                page.keyboard.down(char)
                page.wait_for_timeout(55)
                page.keyboard.up(char)
                page.wait_for_timeout(105)
            page.wait_for_function("document.getElementById('round-progress').textContent.startsWith('1 /')")
            assert payloads and all("text" not in payload for payload in payloads)
            assert "PRIVATE_TEXT" not in str(payloads)
            assert payloads[0]["count"] >= 24 and len(payloads[0]["features"]) == 12
            assert page.get_by_role("button", name="Finish this round").is_disabled()
            page.get_by_role("link", name="Workspace", exact=True).click()
            page.wait_for_url("**/dashboard")
            page.locator("#policy-state").wait_for(state="visible")
            page.wait_for_function("document.getElementById('policy-state').textContent !== 'Checking…'")
            page.screenshot(path=str(tmp_path / "desktop.png"), full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            page.set_viewport_size({"width": 390, "height": 844})
            page.screenshot(path=str(tmp_path / "mobile.png"), full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        thread.join(timeout=5)


def test_browser_passkey_virtual_authenticator(app,tmp_path):
    from conftest import register,verify
    client=app.test_client();register(app,client);verify(app,client,'passkey')
    server=make_server('127.0.0.1',0,app,threaded=True)
    origin=f'http://localhost:{server.server_port}'
    app.config['WEBAUTHN_ORIGIN']=origin
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with playwright.sync_playwright() as runner:
            browser=runner.chromium.launch(headless=True)
            context=browser.new_context()
            context.add_cookies([{'name':'authsense','value':client.get_cookie('authsense').value,'url':origin,'httpOnly':True,'sameSite':'Strict'}])
            page=context.new_page();errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
            cdp=context.new_cdp_session(page);cdp.send('WebAuthn.enable')
            cdp.send('WebAuthn.addVirtualAuthenticator',{'options':{'protocol':'ctap2','transport':'internal','hasResidentKey':True,'hasUserVerification':True,'isUserVerified':True,'automaticPresenceSimulation':True}})
            page.goto(origin+'/settings')
            page.screenshot(path=str(tmp_path/'settings-desktop.png'),full_page=True)
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(tmp_path/'settings-mobile.png'),full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            page.get_by_role('button',name='Register passkey',exact=True).click()
            playwright.expect(page.locator("#passkey-message")).to_contain_text("Passkey registered")
            from authsense.db import get_db
            with app.app_context():get_db().execute('UPDATE sessions SET must_verify=1')
            page.goto(origin+'/dashboard');page.get_by_role('button',name='Verify with passkey and open vault').click()
            page.wait_for_url('**/vault/open');assert 'One-use passkey' in page.content()
            assert not errors
            browser.close()
    finally:server.shutdown();thread.join(timeout=5)
