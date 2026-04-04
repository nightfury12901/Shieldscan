import React, { useEffect, useRef } from 'react';

const CanvasBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let w: number, h: number;
    let bgAnimFrame: number;
    let columns: number;
    let drops: number[] = [];
    const fontSize = 18; // Increased from 14
    // Classic hex/binary with some symbols looks like a security scanner
    const chars = '01#$@&*WXQ[]{}<>+=_-:;010101010101ABDCGEFXH'.split('');

    const resize = () => {
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
      columns = Math.floor(w / fontSize);
      drops = [];
      for (let x = 0; x < columns; x++) {
        // Randomize initial vertical positions so it doesn't all drop at once
        drops[x] = Math.random() * (h / fontSize);
      }
    };

    let mouseX = -1000;
    let mouseY = -1000;
    
    const onMouseMove = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
    };

    const draw = () => {
      // Semi-transparent black to create trailing effect.
      // Adjust alpha for trail length (lower = longer trails)
      ctx.fillStyle = 'rgba(14, 14, 14, 0.15)'; 
      ctx.fillRect(0, 0, w, h);

      ctx.font = `${fontSize}px "DM Mono", monospace`;

      for (let i = 0; i < drops.length; i++) {
        const text = chars[Math.floor(Math.random() * chars.length)];
        
        let tx = i * fontSize;
        let ty = drops[i] * fontSize;

        // Interactive logic: text glows bright white when the cursor is nearby
        const dist = Math.sqrt((tx - mouseX) ** 2 + (ty - mouseY) ** 2);
        
        if (dist < 150) {
          // Extremely bright text under cursor (increased radius)
          ctx.fillStyle = 'rgba(255, 255, 255, 1)'; 
        } else {
          // Normal background matrix color
          ctx.fillStyle = 'rgba(255, 255, 255, 0.2)';
        }

        ctx.fillText(text, tx, ty);

        // Reset drop randomly to create varied flowing column heights
        if (ty > h && Math.random() > 0.975) {
          drops[i] = 0;
        }
        
        // Speed of the rain - reduced from 0.8
        drops[i] += 0.3;
      }
      bgAnimFrame = requestAnimationFrame(draw);
    };

    window.addEventListener('resize', resize);
    window.addEventListener('mousemove', onMouseMove);
    resize();
    bgAnimFrame = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener('resize', resize);
      window.removeEventListener('mousemove', onMouseMove);
      cancelAnimationFrame(bgAnimFrame);
    };
  }, []);

  return <canvas ref={canvasRef} id="bg-canvas" aria-hidden="true" style={{ position: 'fixed', top: 0, left: 0, width: '100%', height: '100%', zIndex: -1, pointerEvents: 'none' }} />;
};

export default CanvasBackground;
