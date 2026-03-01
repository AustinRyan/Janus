import type { Metadata } from "next";
import { MonitorPage } from "@/components/monitor/MonitorPage";

export const metadata: Metadata = {
  title: "Janus Monitor — Production Security Dashboard",
};

export default function Monitor() {
  return <MonitorPage />;
}
