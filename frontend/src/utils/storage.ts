// All state is now held in React component state — no localStorage.
// This module is kept as a no-op stub so import paths don't need changing.

export const storage = {
    isAuthenticated: (): boolean => false,
    setAuthenticated: (_val: boolean): void => {},
    isSettingsUnlocked: (): boolean => false,
    setSettingsUnlocked: (_val: boolean): void => {},
    clearAll: (): void => {},
};
