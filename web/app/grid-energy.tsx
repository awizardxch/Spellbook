"use client";

/* The Forge's background energy, ported from projects/chia-cfmm
 * src/components/GridEnergy.tsx (forge.awizard.dev).
 *
 * Two canvases over the dot grid in globals.css: a static circuit board whose
 * traces run from every card's edges to the nav rails, and a live layer that
 * sends pulses along the dot grid and those traces -- ambient ones on a timer,
 * short bright ones under the pointer. Pointer pulses skip touch, reduced
 * motion, hidden tabs and anything interactive or card-like under the cursor.
 *
 * Differences from the Forge: the Forge scopes cards to its active Radix tab
 * panel; Spellbook has no tabs, so the whole .app-shell is the board, and the
 * cards are this site's own classes (CHIP_SELECTOR). Rails are still any
 * element marked data-circuit-rail -- here, each page's <nav>.
 */

import { useEffect, useRef } from "react";

type Point = { x: number; y: number };
type ChipBounds = { left: number; top: number; width: number; height: number };
type PulseKind = 'grid' | 'circuit';
type Pulse = { paths: Point[][]; born: number; duration: number; interactive: boolean; kind: PulseKind };

const GRID_SIZE = 28;
const GRID_OFFSET = GRID_SIZE / 2;
// Text blocks count as chips too: Spellbook pages put a hero and section heads
// between the nav rail and the cards, and traces must route around the words.
const CHIP_SELECTOR = ".glass, .callout, .dash-panel, .dash-card, .glow-shell, .glow-card, .hero, .dash-hero, .section-head, .footer";
const QUIET_SELECTOR = `button, a, input, textarea, select, [role="dialog"], [role="tab"], ${CHIP_SELECTOR}`;
const snap = (value: number) => Math.round((value - GRID_OFFSET) / GRID_SIZE) * GRID_SIZE + GRID_OFFSET;

export function GridEnergy() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const circuitRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext('2d');
    const circuit = circuitRef.current;
    const board = circuit?.getContext('2d');
    if (!canvas || !context || !circuit || !board) return;

    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let width = 0;
    let height = 0;
    let frame = 0;
    let lastFrame = 0;
    let nextAmbient = 0;
    let lastPointerTime = 0;
    let lastPointer: Point | null = null;
    let pendingPointer: Point | null = null;
    let pulses: Pulse[] = [];
    let routes: Point[][] = [];
    let layoutFrame = 0;
    let layoutSignature = '';
    let chipElements: Element[] = [];
    let chipBounds: ChipBounds[] = [];

    const maskChips = (target: CanvasRenderingContext2D) => {
      for (const chip of chipBounds) {
        target.beginPath();
        target.rect(0, 0, width, height);
        target.rect(chip.left, chip.top, chip.width, chip.height);
        target.clip('evenodd');
      }
    };

    const drawRoute = (corners: Point[]) => {
      const route = [corners[0]];
      for (let corner = 1; corner < corners.length; corner += 1) {
        const previous = corners[corner - 1];
        const point = corners[corner];
        const steps = Math.ceil(Math.max(Math.abs(point.x - previous.x), Math.abs(point.y - previous.y)) / GRID_SIZE);
        for (let step = 1; step <= steps; step += 1) {
          route.push({
            x: previous.x + (point.x - previous.x) * step / steps,
            y: previous.y + (point.y - previous.y) * step / steps,
          });
        }
      }
      routes.push(route);
      board.beginPath();
      board.moveTo(route[0].x, route[0].y);
      for (const point of route.slice(1)) board.lineTo(point.x, point.y);
      board.stroke();
      return route;
    };

    const resize = () => {
      const bounds = canvas.getBoundingClientRect();
      const panel = document.querySelector(".app-shell");
      const candidates = Array.from(panel?.querySelectorAll(CHIP_SELECTOR) ?? []).filter(element => {
        const rect = element.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      });
      const nextChips = candidates.filter(element => !candidates.some(parent => parent !== element && parent.contains(element)));
      for (const element of chipElements) {
        if (!nextChips.includes(element)) layoutObserver.unobserve(element);
      }
      for (const element of nextChips) {
        if (!chipElements.includes(element)) layoutObserver.observe(element);
      }
      chipElements = nextChips;
      const chips = chipElements.map(element => element.getBoundingClientRect()).filter(rect => rect.width > 0 && rect.height > 0);
      const rails = Array.from(document.querySelectorAll('[data-circuit-rail]')).map(element => {
        const rect = element.getBoundingClientRect();
        return { left: rect.left - bounds.left, right: rect.right - bounds.left, y: rect.bottom - bounds.top + 1 };
      });
      width = bounds.width;
      height = bounds.height;
      const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
      const signature = [width, height, pixelRatio, chips.length, ...chips.flatMap(chip => [chip.left, chip.top, chip.width, chip.height]), ...rails.flatMap(rail => [rail.left, rail.right, rail.y])].join(':');
      if (signature === layoutSignature) return;
      layoutSignature = signature;
      canvas.width = Math.round(width * pixelRatio);
      canvas.height = Math.round(height * pixelRatio);
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
      circuit.width = canvas.width;
      circuit.height = canvas.height;
      board.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
      board.strokeStyle = 'rgba(42, 157, 184, 0.22)';
      board.lineWidth = 1;
      board.lineJoin = 'round';
      routes = [];
      pulses = [];
      chipBounds = chips.map(chip => ({ left: chip.left - bounds.left, top: chip.top - bounds.top, width: chip.width, height: chip.height }));
      board.save();
      maskChips(board);
      for (const rail of rails) {
        if (rail.y >= 0 && rail.y <= height) drawRoute([{ x: rail.left, y: rail.y }, { x: rail.right, y: rail.y }]);
      }
      for (let index = 1; index < rails.length; index += 1) {
        const upper = rails[index - 1];
        const lower = rails[index];
        if (lower.y <= upper.y || lower.y < 0 || upper.y > height) continue;
        for (const direction of [-1, 1]) {
          const edge = direction < 0 ? lower.left : lower.right;
          const room = direction < 0 ? edge - upper.left : upper.right - edge;
          const bend = Math.max(0, Math.min(GRID_OFFSET, room, (lower.y - upper.y) / 3));
          drawRoute([
            { x: edge + direction * bend, y: upper.y },
            { x: edge + direction * bend, y: lower.y - bend },
            { x: edge, y: lower.y },
          ]);
        }
      }
      for (const chip of chipBounds) {
        const { left, top } = chip;
        const right = left + chip.width;
        const bottom = top + chip.height;
        const upperRail = rails.filter(rail => rail.y < top).at(-1);
        const sides = [
          { start: { x: left, y: top }, normal: { x: -1, y: 0 }, tangent: { x: 0, y: 1 }, extent: chip.height, space: left },
          { start: { x: right, y: top }, normal: { x: 1, y: 0 }, tangent: { x: 0, y: 1 }, extent: chip.height, space: width - right },
          { start: { x: left, y: top }, normal: { x: 0, y: -1 }, tangent: { x: 1, y: 0 }, extent: chip.width, space: upperRail ? top - upperRail.y + GRID_OFFSET : top },
          { start: { x: left, y: bottom }, normal: { x: 0, y: 1 }, tangent: { x: 1, y: 0 }, extent: chip.width, space: height - bottom },
        ];
        for (const side of sides) {
          let available = side.space - GRID_OFFSET;
          let linkedChip = false;
          for (const neighbor of chipBounds) {
            if (neighbor === chip) continue;
            const neighborRight = neighbor.left + neighbor.width;
            const neighborBottom = neighbor.top + neighbor.height;
            const overlapsRows = neighbor.top < bottom && neighborBottom > top;
            const overlapsColumns = neighbor.left < right && neighborRight > left;
            let gap = Infinity;
            if (side.normal.x === -1 && overlapsRows && neighborRight <= left) gap = left - neighborRight;
            if (side.normal.x === 1 && overlapsRows && neighbor.left >= right) gap = neighbor.left - right;
            if (side.normal.y === -1 && overlapsColumns && neighborBottom <= top) gap = top - neighborBottom;
            if (side.normal.y === 1 && overlapsColumns && neighbor.top >= bottom) gap = neighbor.top - bottom;
            if (gap <= available) {
              available = gap;
              linkedChip = true;
            }
          }
          if (available < 6) continue;
          const count = Math.min(14, Math.floor((side.extent - GRID_SIZE * 2) / GRID_SIZE));
          for (let index = 0; index < count; index += 1) {
            const offset = (side.extent - (count - 1) * GRID_SIZE) / 2 + index * GRID_SIZE;
            const origin = {
              x: side.tangent.x ? snap(side.start.x + offset) : side.start.x,
              y: side.tangent.y ? snap(side.start.y + offset) : side.start.y,
            };
            const fraction = count > 1 ? index / (count - 1) - 0.5 : 0;
            const spread = Math.round(fraction * Math.min(available * 0.45, 168) / GRID_SIZE) * GRID_SIZE;
            const lead = Math.min(GRID_SIZE, available / 3);
            const length = Math.max(lead + Math.abs(spread), available - (index % 3) * GRID_SIZE);
            let connectedToRail = false;
            let corners = [
              origin,
              { x: origin.x + side.normal.x * lead, y: origin.y + side.normal.y * lead },
              {
                x: origin.x + side.normal.x * (lead + Math.abs(spread)) + side.tangent.x * spread,
                y: origin.y + side.normal.y * (lead + Math.abs(spread)) + side.tangent.y * spread,
              },
              {
                x: origin.x + side.normal.x * length + side.tangent.x * spread,
                y: origin.y + side.normal.y * length + side.tangent.y * spread,
              },
            ];
            if (linkedChip) {
              corners = [origin, { x: origin.x + side.normal.x * available, y: origin.y + side.normal.y * available }];
            } else if (side.normal.y === -1 && upperRail) {
              corners = [origin, { x: origin.x, y: upperRail.y }];
              connectedToRail = true;
            }
            const rail = rails[index];
            if (!linkedChip && side.normal.x && rail && rail.y < origin.y && available > lead + origin.y - rail.y + GRID_SIZE) {
              corners = [
                origin,
                { x: origin.x + side.normal.x * lead, y: origin.y },
                { x: origin.x + side.normal.x * (lead + origin.y - rail.y), y: rail.y },
                { x: side.normal.x < 0 ? rail.left : rail.right, y: rail.y },
              ];
              connectedToRail = true;
            }
            const route = drawRoute(corners);
            board.save();
            board.strokeStyle = 'rgba(90, 203, 220, 0.4)';
            board.lineWidth = 3;
            board.beginPath();
            board.moveTo(origin.x, origin.y);
            board.lineTo(origin.x + side.normal.x * Math.min(9, available), origin.y + side.normal.y * Math.min(9, available));
            board.stroke();
            board.restore();
            const terminal = route[route.length - 1];
            board.beginPath();
            board.arc(terminal.x, terminal.y, connectedToRail || linkedChip ? 1.8 : 3.5, 0, Math.PI * 2);
            board.fillStyle = connectedToRail || linkedChip ? 'rgba(90, 203, 220, 0.4)' : '#060810';
            board.fill();
            board.stroke();
          }
        }
      }
      board.restore();
    };

    const scheduleLayout = () => {
      if (layoutFrame) return;
      layoutFrame = window.requestAnimationFrame(() => {
        layoutFrame = 0;
        resize();
      });
    };
    const layoutObserver = new ResizeObserver(scheduleLayout);
    const panelObserver = new MutationObserver(scheduleLayout);
    const shell = document.querySelector('.app-shell');
    if (shell) {
      layoutObserver.observe(shell);
      for (const rail of Array.from(shell.querySelectorAll('[data-circuit-rail]'))) layoutObserver.observe(rail);
      panelObserver.observe(shell, { childList: true, subtree: true, attributes: true, attributeFilter: ['data-state'] });
    }

    const spawn = (origin: Point, now: number, interactive: boolean, kind: PulseKind) => {
      if (pulses.filter(pulse => pulse.interactive === interactive && pulse.kind === kind).length >= (interactive ? 2 : 1)) {
        if (!interactive) return;
        const oldest = pulses.findIndex(pulse => pulse.interactive && pulse.kind === kind);
        pulses.splice(oldest, 1);
      }
      if (kind === 'grid') {
        const paths: Point[][] = [];
        const heading = Math.random() * Math.PI * 2;
        for (let branch = 0; branch < 2; branch += 1) {
          const path = [{ x: snap(origin.x), y: snap(origin.y) }];
          const length = 3 + Math.floor(Math.random() * 3);
          for (let step = 0; step < length; step += 1) {
            const angle = Math.round((heading + branch * Math.PI + (Math.random() - 0.5) * 1.5) / (Math.PI / 4)) * Math.PI / 4;
            const previous = path[path.length - 1];
            const point = {
              x: previous.x + Math.round(Math.cos(angle)) * GRID_SIZE,
              y: previous.y + Math.round(Math.sin(angle)) * GRID_SIZE,
            };
            if (point.x < 0 || point.x > width || point.y < 0 || point.y > height) break;
            path.push(point);
          }
          paths.push(path);
        }
        pulses.push({ paths, born: now, duration: interactive ? 420 : 1800 + Math.random() * 600, interactive, kind });
        return;
      }
      let nearestRoute: Point[] | undefined;
      let nearestIndex = 0;
      let nearestDistance = Infinity;
      for (const route of routes) {
        for (let index = 0; index < route.length; index += 1) {
          const point = route[index];
          if (point.x < 0 || point.x > width || point.y < 0 || point.y > height) continue;
          if (chipBounds.some(chip => point.x > chip.left && point.x < chip.left + chip.width && point.y > chip.top && point.y < chip.top + chip.height)) continue;
          const distance = (point.x - origin.x) ** 2 + (point.y - origin.y) ** 2;
          if (distance < nearestDistance) {
            nearestDistance = distance;
            nearestRoute = route;
            nearestIndex = index;
          }
        }
      }
      if (!nearestRoute) return;
      const length = 3 + Math.floor(Math.random() * 3);
      const paths = [
        nearestRoute.slice(nearestIndex, nearestIndex + length),
        nearestRoute.slice(Math.max(0, nearestIndex - length + 1), nearestIndex + 1).reverse(),
      ];
      pulses.push({ paths, born: now, duration: interactive ? 420 : 1800 + Math.random() * 600, interactive, kind });
    };

    const draw = (now: number) => {
      frame = window.requestAnimationFrame(draw);
      if (now - lastFrame < 1000 / 60 - 1) return;
      lastFrame = now;
      context.clearRect(0, 0, width, height);
      pulses = pulses.filter(pulse => now - pulse.born < pulse.duration);
      if (pendingPointer && now - lastPointerTime >= 40) {
        if (!lastPointer || Math.hypot(pendingPointer.x - lastPointer.x, pendingPointer.y - lastPointer.y) >= 8) {
          spawn(pendingPointer, now, true, 'grid');
          spawn(pendingPointer, now, true, 'circuit');
          lastPointer = pendingPointer;
          lastPointerTime = now;
        }
        pendingPointer = null;
      }
      if (now >= nextAmbient) {
        const origin = { x: Math.random() * width, y: Math.random() * height };
        spawn(origin, now, false, 'grid');
        spawn({ x: width - origin.x, y: Math.random() * height }, now, false, 'circuit');
        nextAmbient = now + 1100 + Math.random() * 450;
      }
      context.save();
      maskChips(context);
      context.lineCap = 'round';
      context.lineJoin = 'round';
      for (const pulse of pulses) {
        const progress = (now - pulse.born) / pulse.duration;
        const envelope = pulse.interactive
          ? Math.min(1, progress / 0.08) * Math.pow(1 - progress, 0.7)
          : Math.sin(progress * Math.PI);
        const peak = pulse.interactive ? 0.18 : 0.4;
        const reach = progress < peak ? progress / peak : (1 - progress) / (1 - peak);
        context.strokeStyle = pulse.interactive ? '#8cefff' : '#35cce6';
        context.fillStyle = '#b9f7ff';
        context.shadowColor = '#00d9ff';
        for (const path of pulse.paths) {
          const visible = reach * (path.length - 1);
          context.beginPath();
          context.moveTo(path[0].x, path[0].y);
          for (let index = 1; index < path.length && index - 1 < visible; index += 1) {
            const previous = path[index - 1];
            const point = path[index];
            const portion = Math.min(1, visible - (index - 1));
            context.lineTo(
              previous.x + (point.x - previous.x) * portion,
              previous.y + (point.y - previous.y) * portion,
            );
          }
          context.globalAlpha = envelope * (pulse.interactive ? 0.09 : 0.06);
          context.lineWidth = 4;
          context.shadowBlur = 8;
          context.stroke();
          context.globalAlpha = envelope * (pulse.interactive ? 0.5 : 0.3);
          context.lineWidth = 0.8;
          context.shadowBlur = 3;
          context.stroke();
          for (let index = 0; index < path.length && index <= visible; index += 1) {
            context.beginPath();
            context.arc(path[index].x, path[index].y, 1.5, 0, Math.PI * 2);
            context.fill();
          }
        }
      }
      context.globalAlpha = 1;
      context.shadowBlur = 0;
      context.restore();
    };

    const resetPointer = () => {
      lastPointer = null;
      pendingPointer = null;
      lastPointerTime = 0;
    };
    const onPointerMove = (event: PointerEvent) => {
      if (reducedMotion.matches || document.hidden || event.pointerType === 'touch') return;
      const target = event.target;
      if (target instanceof Element && target.closest(QUIET_SELECTOR)) {
        resetPointer();
        return;
      }
      pendingPointer = { x: event.clientX, y: event.clientY };
    };

    const syncAnimation = () => {
      window.cancelAnimationFrame(frame);
      pulses = [];
      resetPointer();
      context.clearRect(0, 0, width, height);
      if (!reducedMotion.matches && !document.hidden) {
        nextAmbient = performance.now() + 100;
        frame = window.requestAnimationFrame(draw);
      }
    };

    resize();
    syncAnimation();
    window.addEventListener('resize', scheduleLayout);
    window.addEventListener('scroll', scheduleLayout, true);
    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('blur', resetPointer);
    document.addEventListener('pointerleave', resetPointer);
    document.addEventListener('visibilitychange', syncAnimation);
    reducedMotion.addEventListener('change', syncAnimation);
    return () => {
      window.cancelAnimationFrame(frame);
      window.cancelAnimationFrame(layoutFrame);
      layoutObserver.disconnect();
      panelObserver.disconnect();
      window.removeEventListener('resize', scheduleLayout);
      window.removeEventListener('scroll', scheduleLayout, true);
      window.removeEventListener('pointermove', onPointerMove);
      window.removeEventListener('blur', resetPointer);
      document.removeEventListener('pointerleave', resetPointer);
      document.removeEventListener('visibilitychange', syncAnimation);
      reducedMotion.removeEventListener('change', syncAnimation);
    };
  }, []);

  return (
    <>
      <canvas ref={circuitRef} className="grid-energy" aria-hidden="true" />
      <canvas ref={canvasRef} className="grid-energy" aria-hidden="true" />
    </>
  );
}