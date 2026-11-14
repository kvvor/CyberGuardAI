import { Slot } from "@radix-ui/react-slot";
import { cva } from "class-variance-authority";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";
export const cn=(...inputs)=>twMerge(clsx(inputs));
const variants=cva("inline-flex items-center justify-center gap-2 rounded-lg text-sm font-medium focus-visible:outline-2 disabled:pointer-events-none disabled:opacity-50",{variants:{variant:{default:"primary",outline:"border border-[var(--border)] bg-[var(--raised)]",destructive:"danger"},size:{default:"px-4 py-3",sm:"px-3 py-2"}},defaultVariants:{variant:"default",size:"default"}});
export function Button({className,variant,size,asChild=false,...props}){const Comp=asChild?Slot:"button";return <Comp className={cn(variants({variant,size,className}))} {...props}/>;}
