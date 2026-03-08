document.addEventListener("DOMContentLoaded", () => {

const API_KEY = "b444f63f32ed4481fe2b7a47451bd8f02e466c5a505d6b1f"

const messages = document.getElementById("messages")
const events = document.getElementById("events")

function addMessage(text, cls){
const div = document.createElement("div")
div.className = cls
div.innerText = text
messages.appendChild(div)
messages.scrollTop = messages.scrollHeight
}

window.sendMessage = async function(){

const input = document.getElementById("input")
const text = input.value
if(!text.trim()) return

addMessage("You: " + text, "user")

const res = await fetch("http://127.0.0.1:8000/v1/chat/completions",{
method:"POST",
headers:{
"Content-Type":"application/json",
"X-Wren-Key":API_KEY
},
body:JSON.stringify({
model:"gpt-4o-mini",
messages:[{role:"user",content:text}]
})
})

const data = await res.json()

if(data.error){
    const meta = data.wren_meta || {}
    let blockMsg = "🛡️ BLOCKED BY WREN"
    if(meta.tool_call_detected) blockMsg = "🛠️ TOOL CALL DETECTED & BLOCKED"
    blockMsg += "\nReason: " + (data.reason || "Unknown")
    if(data.risk_score !== undefined || meta.risk_score !== undefined){
        const score = data.risk_score !== undefined ? data.risk_score : meta.risk_score
        blockMsg += "\nRisk Score: " + score.toFixed(4)
    }
    const dtype = data.detection_type || meta.detection_type
    if(dtype){
        blockMsg += "\nClassification: " + dtype
    }
    if(data.signals || meta.signals){
        const s = data.signals || meta.signals
        blockMsg += "\nSignals: ML=" + (s.ml_score||0).toFixed(2) + " | Regex=" + (s.regex_density||0).toFixed(2) + " | Instr=" + (s.instruction_density||0).toFixed(2) + " | Trans=" + (s.translation_flag||0) + " | Edu=" + (s.education_context_flag||0) + " | Tech=" + (s.technical_context_flag||0)
    }
    addMessage(blockMsg, "block")
} else {
    const reply = data.choices[0].message.content
    const meta = data.wren_meta
    let botMsg = reply
    if(meta){
        const s = meta.signals || {}
        if(data.extracted_text && data.extracted_text !== text.trim()) {
            botMsg += "\n\n📄 **Extracted Content:**\n\"" + data.extracted_text + "\""
        }
        if(meta.tool_call_detected) {
            botMsg += "\n\n🛠️ **TOOL CALL DETECTED**"
        }
        botMsg += "\n\n📊 Risk: " + (meta.detection_type || "BENIGN") + " (" + (meta.risk_score || 0.0).toFixed(4) + ")"
        botMsg += "\n\u{1f50d} ML=" + (s.ml_score||0).toFixed(2) + " | Regex=" + (s.regex_density||0).toFixed(2) + " | Instr=" + (s.instruction_density||0).toFixed(2) + " | Trans=" + (s.translation_flag||0) + " | Edu=" + (s.education_context_flag||0) + " | Tech=" + (s.technical_context_flag||0)
    }
    addMessage(botMsg, "bot")
}

input.value=""
}

async function loadEvents(){
try {
const res = await fetch("http://localhost:8000/events", {
  headers: {
    "X-Wren-Key": API_KEY
  }
});

if(!res.ok) return

const data = await res.json()

events.innerHTML=""

if(data.events){
data.events.forEach(e=>{

const div=document.createElement("div")

if(e.action==="blocked"){
div.className="block"
}

if(e.action==="redacted"){
div.className="redact"
}

div.innerText=`${e.timestamp} | ${e.module} | ${e.action} | ${e.reason}`

events.appendChild(div)

})
}
} catch(err) {
// silently ignore fetch errors
}
}

window.handleFile = async function(input, type) {
    const file = input.files[0];
    if(!file) return;

    addMessage("📤 Uploading: " + file.name + " (" + type + ")...", "user");

    try {
        const formData = new FormData();
        formData.append("file", file);

        const res = await fetch("http://127.0.0.1:8000/v1/chat/completions", {
            method: "POST",
            headers: {
                "X-Wren-Key": API_KEY
            },
            body: formData
        });

        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            throw new Error(errData.detail || errData.error || `HTTP ${res.status}`);
        }

        const data = await res.json();
        
        if(data.error){
            const meta = data.wren_meta || {}
            let blockMsg = "🛡️ BLOCKED BY WREN"
            if(meta.tool_call_detected) blockMsg = "🛠️ TOOL CALL DETECTED & BLOCKED"
            blockMsg += "\nReason: " + (data.reason || "Unknown")
            if(data.risk_score !== undefined || meta.risk_score !== undefined){
                const score = data.risk_score !== undefined ? data.risk_score : meta.risk_score
                blockMsg += "\nRisk Score: " + score.toFixed(4)
            }
            const dtype = data.detection_type || meta.detection_type
            if(dtype){
                blockMsg += "\nClassification: " + dtype
            }
            if(data.signals || meta.signals){
                const s = data.signals || meta.signals
                blockMsg += "\nSignals: ML=" + (s.ml_score||0).toFixed(2) + " | Regex=" + (s.regex_density||0).toFixed(2) + " | Instr=" + (s.instruction_density||0).toFixed(2) + " | Trans=" + (s.translation_flag||0) + " | Edu=" + (s.education_context_flag||0) + " | Tech=" + (s.technical_context_flag||0)
            }
            addMessage(blockMsg, "block");
        } else {
            const reply = data.choices[0].message.content;
            const meta = data.wren_meta;
            let botMsg = reply;
            if(meta){
                const s = meta.signals || {};
                if(data.extracted_text) {
                    botMsg += "\n\n📄 **Extracted Content:**\n\"" + data.extracted_text + "\"";
                }
                if(meta.tool_call_detected) {
                    botMsg += "\n\n🛠️ **TOOL CALL DETECTED**"
                }
                botMsg += "\n\n📊 Risk: " + (meta.detection_type || "BENIGN") + " (" + (meta.risk_score || 0.0).toFixed(4) + ")";
                botMsg += "\n\u{1f50d} ML=" + (s.ml_score||0).toFixed(2) + " | Regex=" + (s.regex_density||0).toFixed(2) + " | Instr=" + (s.instruction_density||0).toFixed(2) + " | Trans=" + (s.translation_flag||0) + " | Edu=" + (s.education_context_flag||0) + " | Tech=" + (s.technical_context_flag||0);
            }
            addMessage(botMsg, "bot");
        }
    } catch (err) {
        addMessage("❌ Upload Failed: " + err.message, "block");
    } finally {
        // Clear input
        input.value = "";
    }
}


setInterval(loadEvents, 2000)
loadEvents()
})