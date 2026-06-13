import { ButtonProps } from "@/types/types"; 
export default function Button({
  variant = "primary",
  children,
  onClick,
  disabled = false,
  type = "button",
  className = "",
}: ButtonProps) {
  const variants = {
    primary: "bg-[#1e2a6e] hover:bg-[#162058] text-white",
    danger: "bg-red-600 hover:bg-red-700 text-white",
    secondary: "bg-[#2d2d2d] hover:bg-[#1a1a1a] text-white",
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`px-5 py-2 rounded-full font-semibold text-sm transition-colors disabled:opacity-60 ${variants[variant]} ${className}`}
    >
      {children}
    </button>
  );
}

//! buttons must separated for individual buttons