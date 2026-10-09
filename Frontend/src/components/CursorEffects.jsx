import { useEffect } from 'react';

export default function CursorEffects() {
  useEffect(() => {
    const root = document.documentElement;
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    const fine = matchMedia('(hover: hover) and (pointer: fine)').matches;
    const mouse = { x: -9999, y: -9999 };

    if (!fine || reduce) return;

    const dotEl = document.querySelector('.cursor-dot');
    const ringEl = document.querySelector('.cursor-ring');
    let ringX = 0, ringY = 0, cursorShown = false;

    // Track the cursor
    const handlePointerMove = (e) => {
      if (e.pointerType !== 'mouse') return;
      mouse.x = e.clientX;
      mouse.y = e.clientY;
      root.style.setProperty('--mx', e.clientX + 'px');
      root.style.setProperty('--my', e.clientY + 'px');

      if (!cursorShown) {
        cursorShown = true;
        ringX = e.clientX;
        ringY = e.clientY;
        document.body.classList.add('has-cursor');
      }
      dotEl.style.transform = `translate3d(${e.clientX}px, ${e.clientY}px, 0)`;
    };

    const handleMouseLeave = () => {
      mouse.x = mouse.y = -9999;
    };

    const handlePointerOver = (e) => {
      ringEl.classList.toggle(
        'is-hover',
        !!(e.target.closest && e.target.closest('a, button, [data-hover]'))
      );
    };

    window.addEventListener('pointermove', handlePointerMove, { passive: true });
    document.documentElement.addEventListener('mouseleave', handleMouseLeave);
    document.addEventListener('pointerover', handlePointerOver);

    // Animation loop for smooth ring follow
    let animationFrameId;
    function frame() {
      if (cursorShown) {
        ringX += (mouse.x - ringX) * 0.18;
        ringY += (mouse.y - ringY) * 0.18;
        ringEl.style.transform = `translate3d(${ringX}px, ${ringY}px, 0)`;
      }
      animationFrameId = requestAnimationFrame(frame);
    }
    animationFrameId = requestAnimationFrame(frame);

    return () => {
      window.removeEventListener('pointermove', handlePointerMove);
      document.documentElement.removeEventListener('mouseleave', handleMouseLeave);
      document.removeEventListener('pointerover', handlePointerOver);
      cancelAnimationFrame(animationFrameId);
      document.body.classList.remove('has-cursor');
    };
  }, []);

  return null;
}
