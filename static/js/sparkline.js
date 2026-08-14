/* Small charts, drawn by hand.

   There is no build step and no external script may load, so a charting
   library is not an option -- and for a line of numbers it would be a poor
   trade anyway. An SVG polyline says everything a sparkline needs to. */
import { esc } from "./core.js";

/* One line, sized to fit its own values, with errors drawn over requests. */
export function sparkline(values, opts){
  const o=opts||{};
  const w=o.width||120, h=o.height||24, pad=1;
  const vals=(values||[]).map(v=>Number(v)||0);
  if(!vals.length)return '<span class=sub>&mdash;</span>';
  /* The scale never drops below the floor. Scaled purely to its own peak, a
     dead-flat 1 request a minute fills the box solid and reads as more
     traffic than a real rush on the row above it -- the chart would say the
     opposite of the numbers beside it. With a floor, a trickle draws as the
     low band it is, and anything actually busy still gets its own scale. */
  const top=Math.max(o.floor||1,...vals);
  const step=vals.length>1?(w-pad*2)/(vals.length-1):0;
  const y=v=>h-pad-(v/top)*(h-pad*2);
  const pts=vals.map((v,i)=>(pad+i*step).toFixed(1)+","+y(v).toFixed(1)).join(" ");
  const area=pts+" "+(pad+(vals.length-1)*step).toFixed(1)+","+(h-pad)+" "+pad+","+(h-pad);
  return '<svg class=spark width="'+w+'" height="'+h+'" viewBox="0 0 '+w+" "+h+
    '" preserveAspectRatio=none role=img aria-label="'+esc(o.label||"")+'">'+
    '<polygon points="'+area+'" fill="'+(o.fill||"var(--spark-fill)")+'"/>'+
    '<polyline points="'+pts+'" fill=none stroke="'+(o.stroke||"var(--up)")+
      '" stroke-width="1.5" vector-effect="non-scaling-stroke"/></svg>';
}

/* Requests with errors on top of them: the shape of the traffic and the shape
   of what went wrong, in one place, because the question is always whether
   they happened at the same time. */
export function trafficSpark(series, opts){
  const o=opts||{};
  const req=(series&&series.req)||[], err=((series&&series.e5)||[]);
  if(!req.length)return '<span class=sub>no traffic recorded yet</span>';
  const total=req.reduce((a,b)=>a+b,0), bad=err.reduce((a,b)=>a+b,0);
  if(!total&&!bad)return '<span class=sub>no traffic in the window</span>';
  const w=o.width||120, h=o.height||24;
  /* Ten a minute is the floor for "this chart may fill its box": below that,
     the line stays low, because that is what nearly nothing looks like. The
     errors share the requests' scale -- three errors over three hundred
     requests are a hairline, not a second mountain. */
  const top=Math.max(10,...req,...err);
  let html='<span class=sparkwrap>'+sparkline(req,{width:w,height:h,floor:top,
    label:total+" requests"});
  if(bad)html+=sparkline(err,{width:w,height:h,floor:top,stroke:"var(--down)",
    fill:"var(--spark-fill-bad)",label:bad+" server errors"});
  html+="</span>";
  return html;
}

/* What the line covers, said in words: a chart nobody can date is decoration. */
export function sparkCaption(at){
  if(!at||!at.length)return "";
  const mins=Math.round((at[at.length-1]-at[0])/60);
  if(mins<90)return "last "+mins+" min";
  return "last "+Math.round(mins/60)+" h";
}
