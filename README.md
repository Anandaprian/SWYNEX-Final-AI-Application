# SWYNEX-Final-AI-Application

# PII Guard — Browser Extension (SWYNEX Task 4)

**Prevent accidental PII leaks into AI chatbots.**

PII Guard is a Chrome Extension that intercepts every message you send to ChatGPT, Claude, and Gemini. It scans the text using a local Presidio-based AI engine, with custom rules for Indian PII such as Aadhaar numbers, PAN cards, and +91 phone numbers.

The extension redacts sensitive information, rewrites the text box, and sends only the sanitized version.

If the local AI engine is unreachable, the message is blocked entirely using a fail-closed policy to prevent accidental data leaks.

## 1. Project Structure

This repository contains exactly what you need to run the project:

- `pii_guard.py` — The AI NLP engine (Presidio + spaCy).
- `server.py` — The Flask API that wraps the engine.
- `extension.zip` — The Chrome Extension (Manifest V3).
- `README.md` — This guide.

## 2. Step-by-Step Setup Guide

### Step A: Download the Repository

1. Click the green **Code** button at the top right of this GitHub page.
2. Click **Download ZIP**.
3. Extract the downloaded ZIP file on your computer.

### Step B: Set Up the AI Backend in Google Colab

Since the AI engine (spaCy) requires heavy processing, we run it in Google Colab and expose it through a secure tunnel.

1. Open a new [Google Colab Notebook](https://colab.research.google.com/).
2. Click the **Folder icon** on the left sidebar.
3. Use the upload icon there to upload `pii_guard.py` and `server.py` from your extracted folder directly into the Colab file explorer. They will be uploaded to the root `/` directory.

4. Click **+ Code** to create a new code cell. Run the following commands to install the dependencies and download the tunnel tool:

```bash
!pip install flask flask-cors presidio-analyzer presidio-anonymizer spacy
!python -m spacy download en_core_web_sm

!wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared
!chmod +x cloudflared
```

5. Click **+ Code** again to create another code cell. Run the following commands to move the Python files into Colab's working directory and start the server:

```bash
!mv /server.py /content/
!mv /pii_guard.py /content/

!nohup python server.py > server.log 2>&1 &
```

6. Wait 10–15 seconds for the AI models to load into memory. Click **+ Code** to create another cell and run this command to check whether the server is running:

```bash
!cat server.log
```

You should see:

```text
Serving on http://127.0.0.1:5000
```

7. Click **+ Code** again to create another cell. Run the following command to create a secure public tunnel to your Colab server:

```bash
!./cloudflared tunnel --url http://127.0.0.1:5000
```

**IMPORTANT:** Look at the output and copy the URL that ends in `.trycloudflare.com`.

Example:

https://random-words-1234.trycloudflare.com

Leave this cell running! The tunnel must remain active for the extension to communicate with the backend.

### Step C: Install the Chrome Extension

1. Go to the folder you extracted earlier and extract `extension.zip`.
2. This will give you an `extension` folder.
3. Open the `extension` folder and open `background.js` and `popup.js` in a text editor (such as Notepad).
4. Find this exact line in both files:

```javascript
const API_BASE = "<<<PASTE_THE_COPIED_CLOUDFLARE_URL_HERE>>>";
```

5. Replace `<<<PASTE_THE_COPIED_CLOUDFLARE_URL_HERE>>>` with the Cloudflare URL you copied from Colab. Keep the quotation marks.

Example:

```javascript
const API_BASE = "https://random-words-1234.trycloudflare.com";
```

6. Open Chrome or Brave and navigate to:

```text
chrome://extensions
```

7. Turn on **Developer Mode** (top right).
8. Click **Load unpacked** and select the `extension` folder.
9. Click the PII Guard icon in your browser toolbar.

The status dot should turn Green, indicating that the engine is online.

## 3. Demo & Testing

1. Navigate to [https://chatgpt.com](https://chatgpt.com).

2. Type a message containing fake PII:

   > Hi, my name is Ananda and my email is ananda@example.com.

3. Press Enter.

4. A toast notification will appear, and ChatGPT will receive the sanitized message:

   > Hi, my name is `<PERSON>` and my email is `<EMAIL>`.

### Resume Mode

Toggle this option in the extension popup to also redact:

- Locations (e.g., Delhi).
- URLs.
- Dates of Birth (e.g., 15/08/1998).

### Fail-Closed Policy

If you stop the Cloudflare tunnel in Colab:

- The extension displays a red toast notification.
- The message is blocked from being sent.
- Your original, unredacted text remains in the input box.

This ensures that sensitive information is not accidentally transmitted when the backend is unavailable.

### Return to Normal Mode

To use ChatGPT without PII Guard:

1. Open `chrome://extensions`.
2. Find the PII Guard extension.
3. Turn off the extension using the toggle.
4. Go back to ChatGPT.
5. Reload the ChatGPT page.

ChatGPT will now return to its normal mode without PII Guard intercepting your messages.

## 4. Method & Architecture

### The 5 Loopholes Fixed

**1. Rich-Text Editors:** Uses `execCommand` and native value setters to rewrite `contenteditable` divs (ProseMirror/Quill) used by modern AI chat interfaces.

**2. Race Conditions:** Uses `capture: true` on document-level event listeners to intercept Enter/Send events before React's handlers can process them.

**3. CORS Restrictions:** Routes all API calls through the extension's background service worker (`background.js`), which has the required `host_permissions` to fetch data from the tunnel.

**4. Model Load Times:** The Flask server loads spaCy once during startup, ensuring fast responses of approximately 90 ms under the tested conditions.

**5. Infinite Send Loops:** Uses `isTrusted` checks and an `isProcessing` boolean to ensure programmatic Send clicks are not intercepted again.

### Indian PII Blind Spots

Standard Presidio configurations may miss regional Indian data formats.

To address this, we implemented custom recognition mechanisms:

- **Indian Phone Numbers:** Custom Regex patterns for +91 phone numbers.
- **Aadhaar Numbers:** Custom Regex patterns for 12-digit Aadhaar numbers.
- **PAN Cards:** Custom Regex patterns for the format `ABCDE1234F`.
- **Indian Names and States:** A DenyList containing common Indian names and state names.

These enhancements improve the detection of Indian-specific personally identifiable information (PII).

## 5. Limitations

**Selector Rot:** If ChatGPT redesigns its website, the selectors in `content.js` may need to be updated.

**Main Composer Only:** The extension protects only the main chat box. Uploading files or editing previously sent messages bypasses the guard.

**Threading:** The Flask server uses a thread lock because spaCy is not thread-safe. It handles one message at a time, which is sufficient for personal use.

**Fail-Closed Trade-off:** If the Colab notebook goes idle or the Cloudflare tunnel disconnects, the extension blocks messages until the backend is restarted.

## 6. Ethics & Privacy

### No Data Logging

The Flask server processes text in memory and never logs raw or redacted message content. Only entity counts are tracked.

### Local Ownership

The AI engine runs in your own Google Colab instance and communicates directly with your browser through the tunnel. No third-party privacy tool is involved in processing your message content.

### Fail-Closed Design

In privacy engineering, protecting sensitive information takes priority over uninterrupted user experience.

PII Guard follows this principle: **It is better to block a message than to risk exposing sensitive information.**
