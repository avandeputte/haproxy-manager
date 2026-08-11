/* Shared mutable state.
 *
 * One object rather than seven exported `let`s: a module cannot assign to
 * a binding it imported, so anything written from more than one place has
 * to be a property of something.
 */
export const state = {
  pageTimer: null,   // per-page refresh timer, cleared whenever we navigate
  readOnly: false,   // this node is passive, so the UI is read-only
  who: {authenticated:false,needs_setup:false,username:"",admin_username:"admin"},   // who is signed in, and whether the node still needs setting up
  dnsApis: [],   // the acme.sh DNS hook catalogue, fetched once
  kaDiag: null,   // the last Keepalived diagnosis
  setupIfaceOptions: [],   // interfaces offered by the first-run wizard
  ticking: false,   // a status refresh is already in flight
};
