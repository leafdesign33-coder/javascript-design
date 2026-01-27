(function() {
  "use strict";

  // Navigation data
  const rootArray = [
    { 
      name: "Javascript-design",
      nav: [
        { name: "Startseite", navIcon: "" },
        { name: "Über uns", navIcon: "" },
        { name: "Leistungen", navIcon: "" },
        { name: "Referenzen", navIcon: "" },
        { name: "Kontakt", navIcon: "" }
      ]
    }
  ];

  const container = document.getElementById('root');
  if (!container) return;

  // --- Hamburger icon ---
  const hamburger = document.createElement('div');
  hamburger.id = 'hamburger';
  hamburger.style.width = '35px';
  hamburger.style.height = '25px';
  hamburger.style.display = 'flex';
  hamburger.style.flexDirection = 'column';
  hamburger.style.justifyContent = 'space-between';
  hamburger.style.cursor = 'pointer';
  hamburger.style.marginBottom = '15px';

  for (let i = 0; i < 3; i++) {
    const bar = document.createElement('span');
    bar.style.height = '4px';
    bar.style.width = '100%';
    bar.style.background = '#1a73e8';
    bar.style.borderRadius = '2px';
    bar.style.transition = 'all 0.3s ease';
    hamburger.appendChild(bar);
  }

  container.appendChild(hamburger);

  // --- Full screen overlay nav ---
  const fullNav = document.createElement('div');
  fullNav.id = 'full-nav';
  fullNav.style.position = 'fixed';
  fullNav.style.top = '0';
  fullNav.style.left = '0';
  fullNav.style.width = '100%';
  fullNav.style.height = '100%';
  fullNav.style.background = 'rgba(17,17,17,0.95)';
  fullNav.style.color = '#fff';
  fullNav.style.display = 'flex';
  fullNav.style.flexDirection = 'column';
  fullNav.style.alignItems = 'center';
  fullNav.style.justifyContent = 'center';
  fullNav.style.gap = '30px';
  fullNav.style.transform = 'translateY(-100%)';
  fullNav.style.transition = 'transform 0.4s ease';
  fullNav.style.zIndex = '10000';

  // Populate nav items from rootArray
  rootArray.forEach(rootItem => {
    rootItem.nav.forEach(item => {
      const navItem = document.createElement('div');
      navItem.classList.add('nav-item');
      navItem.textContent = item.name || '';
      navItem.style.fontSize = '2rem';
      navItem.style.cursor = 'pointer';
      navItem.addEventListener('mouseenter', () => {
        navItem.style.color = '#1a73e8';
      });
      navItem.addEventListener('mouseleave', () => {
        navItem.style.color = '#fff';
      });
      fullNav.appendChild(navItem);
    });
  });

  document.body.appendChild(fullNav);

  // Toggle full nav on hamburger click
  hamburger.addEventListener('click', () => {
    fullNav.classList.toggle('open');
    if (fullNav.classList.contains('open')) {
      fullNav.style.transform = 'translateY(0)';
    } else {
      fullNav.style.transform = 'translateY(-100%)';
    }

    // Animate hamburger into X
    hamburger.classList.toggle('open');
    const bars = hamburger.querySelectorAll('span');
    if (hamburger.classList.contains('open')) {
      bars[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
      bars[1].style.opacity = '0';
      bars[2].style.transform = 'rotate(-45deg) translate(5px, -5px)';
    } else {
      bars[0].style.transform = 'rotate(0) translate(0,0)';
      bars[1].style.opacity = '1';
      bars[2].style.transform = 'rotate(0) translate(0,0)';
    }
  });

})();
