// ============================================================================================
// select-enhance.js -- replaces native <select> popups with a custom-drawn, dark-themed
// listbox (Task #20). The `color-scheme` CSS hint does not reliably theme native select
// popups across real browsers/engines, so this draws its own. The underlying native <select>
// is kept in the DOM, fully intact for its `name`/`value`/form submission and for every
// existing piece of code that reads or sets `form.elements[name].value` or listens for a
// native "change" event -- none of that code needed to change. Only direct user interaction
// with the native popup is replaced.
// ============================================================================================

function enhanceSelects() {
  document.querySelectorAll("select").forEach(select => {
    if (select.dataset.enhanced) return;
    if (select.closest(".custom-select")) return;
    select.dataset.enhanced = "1";

    const wrap = document.createElement("span");
    wrap.className = "custom-select";
    select.replaceWith(wrap);
    wrap.append(select);

    // The native element stays for value/name/form/event-listener compatibility, but is
    // removed from the tab order and made unclickable -- the trigger below is what users
    // and assistive tech actually interact with.
    select.tabIndex = -1;
    select.setAttribute("aria-hidden", "true");

    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "custom-select-trigger";
    trigger.setAttribute("role", "combobox");
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");
    wrap.append(trigger);

    const syncTriggerLabel = () => {
      const option = select.options[select.selectedIndex];
      trigger.textContent = option ? option.textContent : "";
      trigger.disabled = select.disabled;
    };
    syncTriggerLabel();

    let menu = null;
    const closeMenu = () => {
      if (!menu) return;
      menu.remove();
      menu = null;
      trigger.setAttribute("aria-expanded", "false");
    };
    const commit = (option, index) => {
      select.selectedIndex = index;
      select.dispatchEvent(new Event("input", { bubbles: true }));
      select.dispatchEvent(new Event("change", { bubbles: true }));
      syncTriggerLabel();
      closeMenu();
      trigger.focus();
    };
    const openMenu = () => {
      if (menu || select.disabled) return;
      menu = document.createElement("div");
      menu.className = "custom-select-menu";
      menu.setAttribute("role", "listbox");
      const rect = trigger.getBoundingClientRect();
      menu.style.left = `${rect.left}px`;
      menu.style.top = `${rect.bottom + 4}px`;
      menu.style.width = `${rect.width}px`;
      [...select.options].forEach((option, index) => {
        const item = document.createElement("div");
        item.className = "custom-select-option" + (index === select.selectedIndex ? " is-selected" : "") + (option.disabled ? " is-disabled" : "");
        item.setAttribute("role", "option");
        item.textContent = option.textContent;
        if (option.disabled) item.setAttribute("aria-disabled", "true");
        else item.addEventListener("click", () => commit(option, index));
        menu.append(item);
      });
      // Dialogs render in the browser's top layer, which sits above ordinary DOM regardless
      // of z-index -- a menu appended to <body> for a select inside a <dialog> would render
      // beneath it. Appending into the dialog keeps the menu in the same stacking context.
      (select.closest("dialog") || document.body).append(menu);
      trigger.setAttribute("aria-expanded", "true");
      const highlighted = () => menu?.querySelector(".is-highlighted") || menu?.querySelector(".is-selected") || menu?.firstElementChild;
      menu.querySelector(".is-selected")?.classList.add("is-highlighted");
      menu._moveHighlight = delta => {
        const items = [...menu.querySelectorAll(".custom-select-option:not(.is-disabled)")];
        if (!items.length) return;
        const current = menu.querySelector(".is-highlighted");
        let index = current ? items.indexOf(current) : -1;
        index = (index + delta + items.length) % items.length;
        menu.querySelectorAll(".is-highlighted").forEach(item => item.classList.remove("is-highlighted"));
        items[index].classList.add("is-highlighted");
        items[index].scrollIntoView({ block: "nearest" });
      };
      menu._chooseHighlighted = () => {
        const item = highlighted();
        if (!item) return;
        const index = [...menu.children].indexOf(item);
        if (index >= 0 && !select.options[index]?.disabled) commit(select.options[index], index);
      };
    };

    trigger.addEventListener("click", () => (menu ? closeMenu() : openMenu()));
    trigger.addEventListener("keydown", event => {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(event.key)) event.preventDefault();
      if (event.key === "ArrowDown") { if (!menu) openMenu(); else menu._moveHighlight(1); }
      else if (event.key === "ArrowUp") { if (!menu) openMenu(); else menu._moveHighlight(-1); }
      else if (event.key === "Enter" || event.key === " ") { if (!menu) openMenu(); else menu._chooseHighlighted(); }
      else if (event.key === "Escape") closeMenu();
      else if (event.key === "Tab") closeMenu();
    });
    document.addEventListener("click", event => { if (menu && !wrap.contains(event.target) && !menu.contains(event.target)) closeMenu(); }, true);

    wrap.__syncTriggerLabel = syncTriggerLabel;
  });
  // Keep every already-enhanced trigger's label in sync with code elsewhere that sets
  // `select.value`/`select.selectedIndex` directly (e.g. renderBackups() populating the
  // scheduled-backup form from saved settings) without going through the custom menu.
  document.querySelectorAll(".custom-select").forEach(wrap => wrap.__syncTriggerLabel?.());
}

document.addEventListener("DOMContentLoaded", enhanceSelects);
setInterval(enhanceSelects, 150);
