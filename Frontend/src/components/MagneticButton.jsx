import { useRef, useEffect } from 'react';

export default function MagneticButton({ children, className = '', ...props }) {
  const zoneRef = useRef(null);
  const btnRef = useRef(null);

  useEffect(() => {
    const zone = zoneRef.current;
    const btn = btnRef.current;
    if (!zone || !btn) return;

    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) return;

    const handlePointerMove = (e) => {
      if (e.pointerType !== 'mouse') return;
      const r = btn.getBoundingClientRect();
      const x = e.clientX - (r.left + r.width / 2);
      const y = e.clientY - (r.top + r.height / 2);
      btn.style.transform = `translate(${x * 0.28}px, ${y * 0.38}px)`;
    };

    const handlePointerLeave = () => {
      btn.style.transform = '';
    };

    zone.addEventListener('pointermove', handlePointerMove);
    zone.addEventListener('pointerleave', handlePointerLeave);

    return () => {
      zone.removeEventListener('pointermove', handlePointerMove);
      zone.removeEventListener('pointerleave', handlePointerLeave);
    };
  }, []);

  return (
    <div ref={zoneRef} className="magnet-zone">
      <button ref={btnRef} className={`magnet-btn ${className}`} {...props}>
        {children}
      </button>
    </div>
  );
}
