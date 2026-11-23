/**
 * Interactive 3D Cyber Background using Three.js
 * Renders a rotating defensive cyber sphere with orbital rings and dynamic particle network
 * reacting to mouse parallax. Throttled and pauses when tab is hidden.
 */

(function () {
  'use strict';

  let scene, camera, renderer, particles, sphereWireframe, outerRing;
  let mouseX = 0, mouseY = 0;
  let targetX = 0, targetY = 0;
  let windowHalfX = window.innerWidth / 2;
  let windowHalfY = window.innerHeight / 2;
  let isVisible = true;
  let animationFrameId = null;

  function init() {
    const canvas = document.getElementById('three-canvas');
    if (!canvas || typeof THREE === 'undefined') return;

    // 1. Scene Setup
    scene = new THREE.Scene();

    // 2. Camera Setup
    camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 1, 2000);
    camera.position.z = 600;

    // 3. Renderer Setup
    renderer = new THREE.WebGLRenderer({
      canvas: canvas,
      alpha: true,
      antialias: window.devicePixelRatio < 2
    });
    renderer.setSize(window.innerWidth, window.innerHeight);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

    // 4. Create 3D Objects
    createParticles();
    createCyberSphere();
    createOrbitalRing();

    // 5. Event Listeners
    window.addEventListener('resize', onWindowResize, false);
    document.addEventListener('mousemove', onDocumentMouseMove, { passive: true });
    document.addEventListener('visibilitychange', onVisibilityChange, false);

    // 6. Start Animation Loop
    animate();
  }

  function createParticles() {
    const count = window.innerWidth < 768 ? 400 : 900;
    const geometry = new THREE.BufferGeometry();
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);

    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const baseColor = isLight ? new THREE.Color(0x0284c7) : new THREE.Color(0x00f2fe);
    const altColor = isLight ? new THREE.Color(0x7c3aed) : new THREE.Color(0x8b5cf6);

    for (let i = 0; i < count; i++) {
      const idx = i * 3;
      // Spread across 3D volume
      positions[idx] = (Math.random() - 0.5) * 1400;
      positions[idx + 1] = (Math.random() - 0.5) * 1400;
      positions[idx + 2] = (Math.random() - 0.5) * 1200;

      const mixed = baseColor.clone().lerp(altColor, Math.random());
      colors[idx] = mixed.r;
      colors[idx + 1] = mixed.g;
      colors[idx + 2] = mixed.b;
    }

    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    const material = new THREE.PointsMaterial({
      size: 3.5,
      vertexColors: true,
      transparent: true,
      opacity: isLight ? 0.45 : 0.65,
      blending: THREE.AdditiveBlending
    });

    particles = new THREE.Points(geometry, material);
    scene.add(particles);
  }

  function createCyberSphere() {
    // Wireframe Icosahedron representing global defensive grid
    const geometry = new THREE.IcosahedronGeometry(200, 2);
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';

    const material = new THREE.MeshBasicMaterial({
      color: isLight ? 0x0284c7 : 0x00f2fe,
      wireframe: true,
      transparent: true,
      opacity: isLight ? 0.12 : 0.22
    });

    sphereWireframe = new THREE.Mesh(geometry, material);
    scene.add(sphereWireframe);
  }

  function createOrbitalRing() {
    const geometry = new THREE.TorusGeometry(280, 1.2, 8, 80);
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';

    const material = new THREE.MeshBasicMaterial({
      color: isLight ? 0x7c3aed : 0x8b5cf6,
      transparent: true,
      opacity: isLight ? 0.18 : 0.3
    });

    outerRing = new THREE.Mesh(geometry, material);
    outerRing.rotation.x = Math.PI / 3;
    scene.add(outerRing);
  }

  function onDocumentMouseMove(event) {
    mouseX = (event.clientX - windowHalfX) * 0.4;
    mouseY = (event.clientY - windowHalfY) * 0.4;
  }

  function onWindowResize() {
    windowHalfX = window.innerWidth / 2;
    windowHalfY = window.innerHeight / 2;

    if (camera && renderer) {
      camera.aspect = window.innerWidth / window.innerHeight;
      camera.updateProjectionMatrix();
      renderer.setSize(window.innerWidth, window.innerHeight);
    }
  }

  function onVisibilityChange() {
    if (document.hidden) {
      isVisible = false;
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
        animationFrameId = null;
      }
    } else {
      isVisible = true;
      animate();
    }
  }

  function animate() {
    if (!isVisible) return;
    animationFrameId = requestAnimationFrame(animate);

    // Smooth camera parallax
    targetX += (mouseX - targetX) * 0.04;
    targetY += (mouseY - targetY) * 0.04;

    camera.position.x = targetX * 0.5;
    camera.position.y = -targetY * 0.5;
    camera.lookAt(scene.position);

    // Object Rotations
    if (particles) {
      particles.rotation.y += 0.0006;
      particles.rotation.x += 0.0003;
    }

    if (sphereWireframe) {
      sphereWireframe.rotation.y += 0.0015;
      sphereWireframe.rotation.x += 0.0008;
    }

    if (outerRing) {
      outerRing.rotation.z += 0.002;
    }

    renderer.render(scene, camera);
  }

  // Update theme colors when user toggles dark/light
  window.updateThreeTheme = function (theme) {
    if (!particles || !sphereWireframe || !outerRing) return;
    const isLight = theme === 'light';

    const cyanColor = isLight ? 0x0284c7 : 0x00f2fe;
    const violetColor = isLight ? 0x7c3aed : 0x8b5cf6;

    sphereWireframe.material.color.setHex(cyanColor);
    sphereWireframe.material.opacity = isLight ? 0.12 : 0.22;

    outerRing.material.color.setHex(violetColor);
    outerRing.material.opacity = isLight ? 0.18 : 0.3;

    particles.material.opacity = isLight ? 0.45 : 0.65;
  };

  // Safe initialize when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

