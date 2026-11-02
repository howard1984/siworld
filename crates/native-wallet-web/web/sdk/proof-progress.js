const stages = {
  preparing: 'Preparing payment inputs',
  reserving: 'Saving encrypted input reservations',
  proving: 'Generating and verifying the post-quantum transaction proof',
  saving: 'Saving the encrypted payment on this device',
};

// A synchronous prover exposes stage boundaries, not a percentage of arithmetic work.
export class ProofProgress {
  constructor(elements, { now = () => performance.now(), every = (fn, ms) => setInterval(fn, ms), stop = id => clearInterval(id) } = {}) {
    this.elements = elements; this.now = now; this.every = every; this.stop = stop;
    this.samples = []; this.active = false;
  }
  start() {
    this.reset(); this.active = true; this.started = this.now();
    this.elements.root.hidden = false;
    this.elements.root.setAttribute('aria-busy', 'true');
    this.elements.bar.removeAttribute('value');
    this.stage('preparing');
    this.timer = this.every(() => this.tick(), 1000);
  }
  stage(name) {
    if (!this.active || !Object.hasOwn(stages, name)) return;
    this.current = name; this.elements.label.textContent = stages[name];
    if (name === 'proving') this.provingStarted = this.now();
    this.tick();
  }
  tick() {
    if (!this.active) return;
    const elapsed = Math.max(0, (this.now() - this.started) / 1000);
    let detail = `${Math.floor(elapsed)} s elapsed. Nothing has been transmitted.`;
    if (this.current === 'proving') {
      const proving = Math.max(0, this.now() - this.provingStarted);
      if (this.samples.length) {
        const estimate = this.samples.reduce((a, b) => a + b, 0) / this.samples.length;
        detail += proving < estimate
          ? ` About ${Math.max(1, Math.ceil((estimate - proving) / 1000))} s remaining, estimated from this session.`
          : ' Taking longer than the session estimate; processing continues.';
      } else {
        detail += ' Desktop reference: about 20–40 s; this device may take longer. A device estimate is available after the first proof.';
      }
    }
    this.elements.detail.textContent = detail;
  }
  finish(milliseconds) {
    if (!this.active) return;
    if (Number.isFinite(milliseconds) && milliseconds > 0) {
      this.samples.push(milliseconds); this.samples = this.samples.slice(-3);
    }
    this.end(); this.elements.bar.value = 1;
    this.elements.label.textContent = 'Transaction proof generated and locally verified';
    this.elements.detail.textContent = 'Ready for your review. Nothing has been transmitted.';
  }
  fail() {
    if (!this.active) return;
    this.end(); this.elements.bar.hidden = true;
    this.elements.label.textContent = 'Payment preparation stopped';
    this.elements.detail.textContent = 'Review the message below. No payment was transmitted by preparation.';
  }
  end() {
    this.active = false; this.stop(this.timer); this.timer = null;
    this.elements.root.setAttribute('aria-busy', 'false');
  }
  reset() {
    this.end(); this.current = null; this.elements.root.hidden = true;
    this.elements.bar.hidden = false; this.elements.bar.removeAttribute('value');
    this.elements.label.textContent = ''; this.elements.detail.textContent = '';
  }
}
