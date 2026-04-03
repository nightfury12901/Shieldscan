import React, { useEffect, useRef } from 'react';

const CanvasBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let w: number, h: number;
    let dots: any[] = [];
    let bgAnimFrame: number;

    const resize = () => {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
      createDots();
    };

    const createDots = () => {
      dots = [];
      const sp = 85;
      for (let r = 0; r < Math.ceil(h / sp) + 1; r++) {
        for (let c = 0; c < Math.ceil(w / sp) + 1; c++) {
          dots.push({
            x: c * sp,
            y: r * sp,
            ox: c * sp,
            oy: r * sp,
            phase: Math.random() * Math.PI * 2,
            speed: 0.001 + Math.random() * 0.002,
            amp: 1 + Math.random() * 2,
          });
        }
      }
    };

    const draw = (t: number) => {
      ctx.clearRect(0, 0, w, h);
      for (const d of dots) {
        d.x = d.ox + Math.sin(t * d.speed + d.phase) * d.amp;
        d.y = d.oy + Math.cos(t * d.speed * 0.7 + d.phase) * d.amp;
      }

      // Dots only (Minimalist)
      for (const d of dots) {
        const cx = w / 2, cy = h / 2;
        const dist = Math.sqrt((d.x - cx) ** 2 + (d.y - cy) ** 2);
        const maxD = Math.sqrt(w * w + h * h) / 2;
        const falloff = 1 - Math.min(dist / maxD, 1);
        ctx.beginPath();
        ctx.arc(d.x, d.y, 1, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,255,255,${0.02 + falloff * 0.06})`;
        ctx.fill();
      }
      bgAnimFrame = requestAnimationFrame(draw);
    };

    window.addEventListener('resize', resize);
    resize();
    bgAnimFrame = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener('resize', resize);
      cancelAnimationFrame(bgAnimFrame);
    };
  }, []);

  return <canvas ref={canvasRef} id="bg-canvas" aria-hidden="true" />;
};

export default CanvasBackground;
