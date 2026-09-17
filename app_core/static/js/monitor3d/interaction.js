import * as THREE from "three";

// Picking: walks from whatever mesh was hit to its parent Group's userData.
// Single click = select, double-click = drill/expand, mousemove = hover.
export function attachInteraction(domElement, camera, pickableGroups, { onSelect, onDrillDown, onHover }) {
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();

  function pick(event) {
    const rect = domElement.getBoundingClientRect();
    pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(pointer, camera);
    const meshes = pickableGroups().map((g) => g.userData.mesh);
    const hits = raycaster.intersectObjects(meshes, false);
    return hits.length ? hits[0].object.userData : null;
  }

  domElement.addEventListener("click", (event) => {
    const hit = pick(event);
    if (hit) onSelect?.(hit);
  });
  domElement.addEventListener("dblclick", (event) => {
    const hit = pick(event);
    if (hit) onDrillDown?.(hit);
  });
  let lastHoverId = null;
  domElement.addEventListener("mousemove", (event) => {
    const hit = pick(event);
    const id = hit?.id || null;
    if (id !== lastHoverId) {
      lastHoverId = id;
      onHover?.(hit);
    }
  });
}
