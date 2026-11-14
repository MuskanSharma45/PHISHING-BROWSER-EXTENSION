// background.js — Manifest V3 service worker
// Minimal background script; all logic is in popup.js

chrome.runtime.onInstalled.addListener(() => {
  console.log("Phishing Website Detector installed.");
});
