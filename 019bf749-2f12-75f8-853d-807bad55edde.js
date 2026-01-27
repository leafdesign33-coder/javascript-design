(function() {
  "use strict";

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
  Object.assign(fullNav.style, {
    position: 'fixed',
    top: '0',
    left: '0',
    width: '100%',
    height: '100%',
    background: 'rgba(17,17,17,0.95)',
    color: '#fff',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '30px',
    transform: 'translateY(-100%)',
    transition: 'transform 0.4s ease',
    zIndex: '10000',
  });

  // --- Close button ---
  const closeBtn = document.createElement('button');
  closeBtn.textContent = '✕ Schließen';
  Object.assign(closeBtn.style, {
    position: 'absolute',
    top: '20px',
    right: '30px',
    fontSize: '1.5rem',
    background: 'transparent',
    border: 'none',
    color: '#fff',
    cursor: 'pointer'
  });
  closeBtn.addEventListener('click', () => {
    fullNav.classList.remove('open');
    fullNav.style.transform = 'translateY(-100%)';
    // Reset hamburger icon
    hamburger.classList.remove('open');
    const bars = hamburger.querySelectorAll('span');
    bars[0].style.transform = 'rotate(0) translate(0,0)';
    bars[1].style.opacity = '1';
    bars[2].style.transform = 'rotate(0) translate(0,0)';
  });
  fullNav.appendChild(closeBtn);

  // Populate nav items from rootArray
  rootArray.forEach(rootItem => {
    rootItem.nav.forEach(item => {
      const navItem = document.createElement('div');
      navItem.classList.add('nav-item');
      navItem.textContent = item.name || '';
      navItem.style.fontSize = '2rem';
      navItem.style.cursor = 'pointer';
      navItem.addEventListener('mouseenter', () => navItem.style.color = '#1a73e8');
      navItem.addEventListener('mouseleave', () => navItem.style.color = '#fff');
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
