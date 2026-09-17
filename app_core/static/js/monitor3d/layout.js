// Deterministic layout: a row of boxes is centered and wraps once too wide.
// Vertical (Y) position is decided by the caller per hierarchy level.

export function computeRowPositions(count, { spacing = 14, maxPerRow = 6 } = {}) {
  const positions = [];
  const rows = Math.max(1, Math.ceil(count / maxPerRow));
  let index = 0;
  for (let row = 0; row < rows; row++) {
    const itemsInRow = Math.min(maxPerRow, count - row * maxPerRow);
    const rowWidth = (itemsInRow - 1) * spacing;
    for (let col = 0; col < itemsInRow; col++) {
      positions[index] = { x: col * spacing - rowWidth / 2, z: row * spacing * 0.7 };
      index++;
    }
  }
  return positions;
}

export function applyRowLayout(groups, { y = 0, spacing = 14, maxPerRow = 6, zOffset = 0 } = {}) {
  const positions = computeRowPositions(groups.length, { spacing, maxPerRow });
  groups.forEach((group, i) => {
    group.position.set(positions[i].x, y, positions[i].z + zOffset);
  });
}
