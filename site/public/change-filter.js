const impact = document.querySelector("#impact-filter");
const search = document.querySelector("#change-search");

if (impact instanceof HTMLSelectElement && search instanceof HTMLInputElement) {
  const apply = () => {
    document.querySelectorAll("#change-list article").forEach((item) => {
      if (!(item instanceof HTMLElement)) return;
      const impactMatch = !impact.value || item.dataset.impacts?.includes(impact.value);
      const textMatch =
        !search.value || item.dataset.text?.includes(search.value.toLowerCase());
      item.hidden = !(impactMatch && textMatch);
    });
  };
  impact.addEventListener("change", apply);
  search.addEventListener("input", apply);
}
