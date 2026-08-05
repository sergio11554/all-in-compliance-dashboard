(function attachAccessControl(global) {
  "use strict";

  function createAccessControl(options = {}) {
    const rolePermissions = options.rolePermissions || {};
    const submitterRoles = new Set(options.submitterRoles || []);

    function permissionsFor(user) {
      if (!user) return [];
      const fallback = Array.isArray(rolePermissions[user.role]) ? rolePermissions[user.role] : [];
      const supplied = Array.isArray(user.permissions) ? user.permissions : [];
      return Array.from(new Set([...fallback, ...supplied]));
    }

    function hasPermission(user, permission, anonymousAllowed = true) {
      if (!user) return Boolean(anonymousAllowed);
      if (user.platformAdmin) return true;
      return permissionsFor(user).includes(permission);
    }

    function isAdmin(user) {
      return Boolean(user && hasPermission(user, "admin", false));
    }

    function canEditWorkspace(user) {
      return hasPermission(user, "saveWorkspace");
    }

    function canReviewDocuments(user) {
      return hasPermission(user, "reviewDocument");
    }

    function canSubmitDocuments(user) {
      if (!user) return true;
      return hasPermission(user, "uploadFile", false) || submitterRoles.has(user.role);
    }

    function canSubmitWorkspace(user) {
      if (!user) return true;
      return hasPermission(user, "submitWorkspace", false) || submitterRoles.has(user.role);
    }

    function canVersionDocuments(user) {
      return hasPermission(user, "versionFile");
    }

    function canDownloadDocuments(user) {
      return hasPermission(user, "downloadFile");
    }

    function canUseConsultantArea(user, localUnlocked = false) {
      if (!user) return Boolean(localUnlocked);
      return Boolean(user.platformAdmin || ["admin", "consultant"].includes(user.role));
    }

    function isCustomerWorkspaceUser(user) {
      if (!user) return false;
      return !user.platformAdmin && !["admin", "consultant"].includes(user.role);
    }

    function canAccessView(user, view, context = {}) {
      const presentationMode = context.customerPresentationMode !== false;
      const consultantUnlocked = Boolean(context.consultantUnlocked);
      if (view === "consultant") return canUseConsultantArea(user, consultantUnlocked) || !presentationMode;
      if (view === "clients") {
        if (!user) return !presentationMode;
        return isAdmin(user) || canReviewDocuments(user);
      }
      if (view === "review") return canReviewDocuments(user) || !presentationMode;
      if (["team", "production", "backup", "quarantine"].includes(view)) {
        if (!user) return !presentationMode;
        return isAdmin(user);
      }
      if (["lifecycle", "operations", "jobs"].includes(view)) return Boolean(user?.platformAdmin) || !presentationMode;
      if (view === "audittrail") return canReviewDocuments(user) || isAdmin(user) || !presentationMode;
      return true;
    }

    return Object.freeze({
      permissionsFor,
      hasPermission,
      isAdmin,
      canEditWorkspace,
      canReviewDocuments,
      canSubmitDocuments,
      canSubmitWorkspace,
      canVersionDocuments,
      canDownloadDocuments,
      canUseConsultantArea,
      isCustomerWorkspaceUser,
      canAccessView
    });
  }

  global.SFMAccessControl = Object.freeze({ createAccessControl });
})(typeof window !== "undefined" ? window : globalThis);
