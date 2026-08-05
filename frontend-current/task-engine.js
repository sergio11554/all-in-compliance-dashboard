(function attachTaskEngine(global) {
  "use strict";

  function createTaskEngine(options = {}) {
    const today = typeof options.today === "function"
      ? options.today
      : () => new Date().toISOString().slice(0, 10);

    function isDone(task = {}) {
      return String(task.status || "") === "Erledigt";
    }

    function isOpen(task = {}) {
      return !isDone(task);
    }

    function isRework(task = {}) {
      return task.workflowType === "review-rework"
        || task.source === "Berater-Rückgabe"
        || Boolean(task.reviewReturnStatus);
    }

    function isOverdue(task = {}, referenceDate = today()) {
      return isOpen(task) && Boolean(task.due) && String(task.due) < String(referenceDate);
    }

    function priority(task = {}, referenceDate = today()) {
      if (isDone(task)) return 0;
      if (isRework(task)) return 100;
      if (String(task.status || "") === "Blockiert") return 96;
      if (isOverdue(task, referenceDate)) return 92;
      if (String(task.status || "") === "In Arbeit") return 65;
      return 54;
    }

    function sort(tasks = [], referenceDate = today()) {
      return tasks
        .map((task, index) => ({ task, index }))
        .sort((left, right) => {
          const priorityDifference = priority(right.task, referenceDate) - priority(left.task, referenceDate);
          if (priorityDifference) return priorityDifference;
          const leftDue = left.task.due || "9999-12-31";
          const rightDue = right.task.due || "9999-12-31";
          const dueDifference = String(leftDue).localeCompare(String(rightDue));
          if (dueDifference) return dueDifference;
          const titleDifference = String(left.task.title || "").localeCompare(String(right.task.title || ""));
          return titleDifference || left.index - right.index;
        })
        .map(({ task }) => task);
    }

    function metrics(tasks = [], referenceDate = today()) {
      const rows = Array.isArray(tasks) ? tasks : [];
      return {
        total: rows.length,
        done: rows.filter(isDone).length,
        open: rows.filter(isOpen).length,
        blocked: rows.filter((task) => isOpen(task) && String(task.status || "") === "Blockiert").length,
        overdue: rows.filter((task) => isOverdue(task, referenceDate)).length,
        rework: rows.filter((task) => isOpen(task) && isRework(task)).length
      };
    }

    return Object.freeze({ isDone, isOpen, isRework, isOverdue, priority, sort, metrics });
  }

  global.SFMTaskEngine = Object.freeze({ createTaskEngine });
})(typeof window !== "undefined" ? window : globalThis);
