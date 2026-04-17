import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

// Click-and-drag horizontal scrolling for .mobile-scroll-wrapper tables.
// Delegated at the document level so it picks up dynamically rendered tables.
(() => {
  let dragState = null;
  const isInteractive = (el) =>
    !!el.closest('button, a, input, select, textarea, label, [role="button"], .recharts-wrapper');

  document.addEventListener('mousedown', (e) => {
    if (e.button !== 0) return;
    const wrapper = e.target.closest('.mobile-scroll-wrapper');
    if (!wrapper) return;
    if (isInteractive(e.target)) return;
    if (wrapper.scrollWidth <= wrapper.clientWidth) return;
    dragState = {
      wrapper,
      startX: e.pageX,
      startScroll: wrapper.scrollLeft,
      moved: false,
    };
  });

  document.addEventListener('mousemove', (e) => {
    if (!dragState) return;
    const dx = e.pageX - dragState.startX;
    if (!dragState.moved && Math.abs(dx) > 4) {
      dragState.moved = true;
      dragState.wrapper.style.cursor = 'grabbing';
      dragState.wrapper.style.userSelect = 'none';
    }
    if (dragState.moved) {
      dragState.wrapper.scrollLeft = dragState.startScroll - dx;
      e.preventDefault();
    }
  });

  const endDrag = () => {
    if (!dragState) return;
    const state = dragState;
    dragState = null;
    state.wrapper.style.cursor = '';
    state.wrapper.style.userSelect = '';
    if (state.moved) {
      // Swallow the click that fires after mouseup so rows don't toggle open.
      const swallow = (ev) => {
        ev.stopPropagation();
        ev.preventDefault();
        document.removeEventListener('click', swallow, true);
      };
      document.addEventListener('click', swallow, true);
    }
  };
  document.addEventListener('mouseup', endDrag);
  document.addEventListener('mouseleave', endDrag);
})();

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
