import { useRef, useEffect } from 'react';

export default function TiltCard({ children, className = '', ...props }) {
  const cardRef = useRef(null);

  useEffect(() => {
    const card = cardRef.current;
    if (!card) return;

    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) return;

    const handlePointerMove = (e) => {
      if (e.pointerType !== 'mouse') return;
      const r = card.getBoundingClientRect();
      const px = (e.clientX - r.left) / r.width;
      const py = (e.clientY - r.top) / r.height;
      card.style.setProperty('--ry', ((px - 0.5) * 9).toFixed(2) + 'deg');
      card.style.setProperty('--rx', ((0.5 - py) * 9).toFixed(2) + 'deg');
      card.style.setProperty('--sx', (px * 100).toFixed(1) + '%');
      card.style.setProperty('--sy', (py * 100).toFixed(1) + '%');
    };

    const handlePointerLeave = () => {
      ['--rx', '--ry'].forEach((p) => card.style.removeProperty(p));
    };

    card.addEventListener('pointermove', handlePointerMove);
    card.addEventListener('pointerleave', handlePointerLeave);

    return () => {
      card.removeEventListener('pointermove', handlePointerMove);
      card.removeEventListener('pointerleave', handlePointerLeave);
    };
  }, []);

  return (
    <div ref={cardRef} className={`tilt-card ${className}`} {...props}>
      {children}
    </div>
  );
}
