/* Local startup visualization. Stage changes require actual application events. */
(() => {
  "use strict";
  const root = document.getElementById("startup-stage");
  if (!root) return;
  const ns = "http://www.w3.org/2000/svg";
  function node(tag, attrs = {}, parent) {
    const el = document.createElementNS(ns, tag);
    for (const [key, value] of Object.entries(attrs)) el.setAttribute(key, String(value));
    if (parent) parent.append(el);
    return el;
  }
  const visual = root.querySelector(".startup-visual");
  if (visual && !visual.querySelector("svg")) {
    const svg = node("svg", {viewBox: "0 0 650 335", "aria-hidden": "true"}, visual);
    const title = node("title", {}, svg);
    title.textContent = "A shipping container with changing parcels; decorative activity only";
    node("ellipse", {cx: 336, cy: 282, rx: 237, ry: 22, fill: "#14161c"}, svg);
    node("path", {d: "M88 135 424 62 558 129 221 203Z", fill: "#292d35", stroke: "#626873"}, svg);
    node("path", {d: "M88 135 221 203 221 279 88 211Z", fill: "#141820", stroke: "#505661"}, svg);
    node("path", {d: "M221 203 558 129 558 205 221 279Z", fill: "#181b23", stroke: "#555b67"}, svg);
    for (let n=0; n<13; n++) {
      const x=235+n*25, y=200-n*5.49;
      node("path", {d:`M${x} ${y}v68`, class:"startup-ribs"}, svg);
    }
    node("path", {d: "M103 144 420 75 541 135 224 205Z", fill: "#0e1117", stroke: "#3a404b"}, svg);
    const parcels = node("g", {}, svg);
    for (let row=0; row<2; row++) for (let col=0; col<6; col++) {
      const x=141+col*46+row*49, y=139-col*10+row*25;
      const base = node("g", {transform:`translate(${x} ${y})`}, parcels);
      const parcel = node("g", {class:`startup-parcel startup-parcel-${row*6+col}`, "data-tone": ["red","dark","light"][(col+row)%3]}, base);
      node("path", {d:"M0 0 34-7 54 3 20 11Z", class:"parcel-top"}, parcel);
      node("path", {d:"M0 0 20 11 20 45 0 34Z", class:"parcel-side"}, parcel);
      node("path", {d:"M20 11 54 3 54 37 20 45Z", class:"parcel-front"}, parcel);
      node("path", {d:"M15-3 35 7 35 41", stroke:"#e7c2c5", opacity:.26, "stroke-width":2, fill:"none"}, parcel);
    }
    node("path", {d:"M109 183 425 114 541 172 224 242Z", fill:"none", stroke:"#f04451", "stroke-width":1, class:"startup-scan"}, svg);
    node("path", {d:"M221 244 558 170 558 205 221 279Z", fill:"#242730", stroke:"#626873"}, svg);
    for (let n=0; n<13; n++) {
      const x=235+n*25, y=241-n*5.49;
      node("path", {d:`M${x} ${y}v28`, class:"startup-ribs"}, svg);
    }
    node("path", {d:"M88 180 221 244 221 279 88 211Z", fill:"#1e212a", stroke:"#585e69"}, svg);
    node("path", {d:"M98 199 209 255", stroke:"#b1293b", "stroke-width":3}, svg);
    node("path", {d:"M232 264 545 195", stroke:"#962538", "stroke-width":2}, svg);
  }
  const brand = root.querySelector("[data-startup-logo]");
  if (brand && !brand.querySelector("svg")) {
    const logo=node("svg",{viewBox:"0 0 100 100","aria-hidden":"true"},brand);
    const colors=["#2f020a","#9d1021","#570916","#920e21","#e62c37","#580815","#5c0515","#b21327","#580c19"];
    colors.forEach((color,i)=>node("rect",{x:(i%3)*35,y:Math.floor(i/3)*35,width:30,height:30,fill:color},logo));
  }
  const profile=root.dataset.profile === "miner" ? "miner" : "wallet";
  const steps=profile === "miner"
    ? ["CPU & configuration", "Accepted history", "Native proof system", "Mining service"]
    : ["Local service", "Authenticated session", "Protected wallet", "Verified history"];
  const list=root.querySelector("[data-startup-steps]");
  if (list) steps.forEach((label,i)=>{
    const item=document.createElement("li");item.textContent=label;item.dataset.number=String(i+1).padStart(2,"0");list.append(item);
  });
  const label=root.querySelector("[data-startup-label]");
  const detail=root.querySelector("[data-startup-detail]");
  const toggle=root.querySelector("[data-startup-toggle]");
  const reduce=window.matchMedia("(prefers-reduced-motion: reduce)");
  let manualPause=false;
  function motion() {
    const paused=manualPause||reduce.matches||document.hidden;
    root.dataset.motion=paused?"paused":"running";
    if(toggle){toggle.textContent=paused?"Motion paused":"Pause motion";toggle.setAttribute("aria-pressed",String(paused));toggle.disabled=reduce.matches;}
  }
  if(toggle) toggle.addEventListener("click",()=>{manualPause=!manualPause;motion();});
  document.addEventListener("visibilitychange",motion);
  reduce.addEventListener("change",motion);
  function update({stage=0,state="active",label:message="Waiting for startup",detail:explanation="Stage progress follows verified application events."}={}) {
    if(!Number.isInteger(stage)||stage<0||stage>4||!["active","ready","error"].includes(state))return false;
    if(state==="ready"&&stage!==4)return false;
    root.dataset.state=state;
    if(label)label.textContent=String(message).slice(0,160);
    if(detail)detail.textContent=String(explanation).slice(0,320);
    if(list)Array.from(list.children).forEach((item,i)=>{
      item.dataset.state=i<stage?"done":i===stage?(state==="error"?"error":"active"):"pending";
    });
    motion();return true;
  }
  const states={
    starting:{stage:0,label:"Starting local wallet"},
    auth:{stage:1,label:"Authenticate this local session"},
    locked:{stage:2,label:"Wallet is locked",detail:"Unlock the protected wallet to scan verified history."},
    unlocked:{stage:3,label:"Wallet unlocked; history not verified",detail:"Independently verify and scan accepted history before using a balance."},
    rescanning:{stage:3,label:"Verifying and scanning history",detail:"Balances become available only after independent verification completes."},
    ready:{stage:4,state:"ready",label:"Wallet scan verified",detail:"The displayed balances refer to the verified chain snapshot."},
    error:{stage:0,state:"error",label:"Startup requires attention",detail:"Resolve the reported error before continuing."},
  };
  window.SiworldStartup=Object.freeze({update,setState(value){
    if(!value||!Object.hasOwn(states,value.phase))return false;
    return update({...states[value.phase],...(typeof value.message==="string"?{detail:value.message}:{}),...(value.phase==="error"&&Number.isInteger(value.stage)?{stage:value.stage}:{})});
  }});
  update();motion();
})();
