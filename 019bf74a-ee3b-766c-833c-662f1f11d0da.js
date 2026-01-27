"use strict";

/* ===================== ZERO-TRUST CONSOLE ONLY ===================== */
/*
  - Kein DOM-Output, alles nur in console.log
  - Eingaben simuliert über Array oder prompt()
  - Alles validieren und sanitizen
  - Zufällige Request-IDs
  - Schutz gegen XSS / Code Injection
*/

/* ----------------- UTIL ----------------- */
function sanitize(str){
    // HTML & JS injection safe
    return str.replace(/[<>"'`;]/g, '');
}

function generateRequestID(){
    return crypto.randomUUID();
}

function secureLog(msg){
    console.log('[SECURE]', msg);
}

/* ----------------- INPUT VALIDATION ----------------- */
function validateInput(str){
    if(typeof str !== "string") return false;
    if(str.length > 100) return false; // max length
    if(/[<>]/.test(str)) return false; // basic XSS filter
    return true;
}

/* ----------------- SECURE STATE ----------------- */
const state = (() => {
    let _data = {};
    return {
        set: (key,val)=>{
            if(typeof key==="string" && typeof val==="string") _data[key]=val;
        },
        get: (key)=>_data[key] || null,
        clear: ()=>{ _data={}; }
    };
})();

/* ----------------- SIMULATED INPUTS ----------------- */
const simulatedInputs = [
    "Hello World",
    "<script>alert('XSS')</script>",
    "ValidInput123",
    "DROP TABLE users;",
    "🚀 Secure Input"
];

simulatedInputs.forEach(input => {
    if(!validateInput(input)){
        secureLog('Ungültige Eingabe erkannt: ' + sanitize(input));
        return;
    }

    const requestID = generateRequestID();
    state.set(requestID, input);

    secureLog(`RequestID: ${requestID} | Input: ${sanitize(input)}`);
});

/* ----------------- PROTECTIONS ----------------- */
window.addEventListener('error', e => {
    secureLog('JS Error captured: ' + e.message);
});

window.addEventListener('unhandledrejection', e => {
    secureLog('Unhandled Promise rejection: ' + e.reason);
});

/* ----------------- SUMMARY ----------------- */
secureLog('Zero-Trust JS ausgeführt. Total Inputs gespeichert: ' + Object.keys(state).length);
