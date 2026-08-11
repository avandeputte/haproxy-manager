// Sorting is separated from the DOM so the part that decides the order can be
// checked directly. These are the shapes real columns hold.
import "./stub-dom.mjs";
const { sortValue, compareValues, sortRows } = await import(process.cwd()+"/static/js/core.js");

let fail = 0;
const ok = (c,m) => { console.log((c?"  PASS  ":"  FAIL  ")+m); if(!c) fail++; };
const order = (vals,dir) => sortRows(vals.map(v=>({key:[v]})),0,dir).map(r=>r.key[0]);

ok(order(["10","9","100"],"asc").join()==="9,10,100",
   "numbers sort numerically, not as text");
ok(order(["1.2 GB","900 MB","12 kB"],"asc").join()==="12 kB,900 MB,1.2 GB",
   "byte sizes sort by what they mean");
ok(order(["2 days","30 mins","5 h"],"asc").join()==="30 mins,5 h,2 days",
   "durations sort by length");
ok(order(["beta","Alpha","gamma"],"asc").join()==="Alpha,beta,gamma",
   "text sorts case-insensitively");
ok(order(["srv10","srv9","srv1"],"asc").join()==="srv1,srv9,srv10",
   "names with numbers sort naturally");
ok(order(["b","—","a"],"asc").slice(-1)[0]==="—" &&
   order(["b","—","a"],"desc").slice(-1)[0]==="—",
   "a blank stays at the bottom whichever way it is sorted");
ok(order(["UP","5","DOWN"],"asc").join()==="5,DOWN,UP",
   "numbers come before words");
ok(order(["1","2","3"],"desc").join()==="3,2,1", "descending reverses");
ok(compareValues("","")===0 && compareValues("a","a")===0, "equal values compare equal");

// stability: rows that tie keep their original order
const tied = [{key:["x"],id:1},{key:["x"],id:2},{key:["x"],id:3}];
ok(sortRows(tied,0,"asc").map(r=>r.id).join()==="1,2,3", "ties keep their order");

console.log(fail ? "\n"+fail+" FAILED" : "\nsorting puts things in the right order");
process.exit(fail?1:0);
