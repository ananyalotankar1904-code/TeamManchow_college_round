import React, { createContext, useContext, useState, useCallback } from 'react';
import { CheckCircle2, AlertTriangle, XCircle, Info, X } from 'lucide-react';

export interface ToastMessage {
  id: string;
  type: 'success' | 'warning' | 'error' | 'info';
  title?: string;
  message: string;
  duration?: number;
}

interface ToastContextType {
  showToast: (toast: Omit<ToastMessage, 'id'>) => void;
  showSuccess: (message: string, title?: string) => void;
  showError: (message: string, title?: string) => void;
  showInfo: (message: string, title?: string) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const showToast = useCallback(
    ({ type, title, message, duration = 3500 }: Omit<ToastMessage, 'id'>) => {
      const id = Math.random().toString(36).substring(2, 9);
      const newToast: ToastMessage = { id, type, title, message, duration };
      setToasts((prev) => [...prev, newToast]);

      if (duration > 0) {
        setTimeout(() => {
          removeToast(id);
        }, duration);
      }
    },
    [removeToast]
  );

  const showSuccess = useCallback((message: string, title?: string) => {
    showToast({ type: 'success', title, message });
  }, [showToast]);

  const showError = useCallback((message: string, title?: string) => {
    showToast({ type: 'error', title, message });
  }, [showToast]);

  const showInfo = useCallback((message: string, title?: string) => {
    showToast({ type: 'info', title, message });
  }, [showToast]);

  return (
    <ToastContext.Provider value={{ showToast, showSuccess, showError, showInfo }}>
      {children}
      {/* Toast Render Container */}
      <div
        aria-live="polite"
        className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-md w-full pointer-events-none"
      >
        {toasts.map((toast) => {
          const isSuccess = toast.type === 'success';
          const isWarning = toast.type === 'warning';
          const isError = toast.type === 'error';

          return (
            <div
              key={toast.id}
              className={`pointer-events-auto flex items-start gap-3 p-3 rounded border shadow-elevated transition-all duration-200 ${
                isSuccess
                  ? 'bg-[#1D3D33] border-[#285547] text-[#A6D6B7]'
                  : isWarning
                  ? 'bg-[#332E1E] border-[#4A4228] text-[#E2C98F]'
                  : isError
                  ? 'bg-[#4A2F31] border-[#5A3A3C] text-[#F0B3AA]'
                  : 'bg-[#073642] border-[#124A58] text-[#E3EEEE]'
              }`}
            >
              <div className="mt-0.5 shrink-0">
                {isSuccess && <CheckCircle2 className="w-4 h-4 text-[#78B993]" />}
                {isWarning && <AlertTriangle className="w-4 h-4 text-[#C8AE5A]" />}
                {isError && <XCircle className="w-4 h-4 text-[#D9776B]" />}
                {!isSuccess && !isWarning && !isError && <Info className="w-4 h-4 text-[#6DBAC6]" />}
              </div>
              <div className="flex-1 text-xs">
                {toast.title && <div className="font-semibold mb-0.5">{toast.title}</div>}
                <div className="opacity-90">{toast.message}</div>
              </div>
              <button
                onClick={() => removeToast(toast.id)}
                className="shrink-0 text-[#8CA3A8] hover:text-[#E3EEEE] transition-colors"
                aria-label="Dismiss toast"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = () => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};
