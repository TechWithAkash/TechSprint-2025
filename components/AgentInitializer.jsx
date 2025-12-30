"use client";

import { useEffect } from "react";
import { initializeAgents } from "@/lib/agents";
import { eventBus } from "@/lib/events";

export default function AgentInitializer() {
  useEffect(() => {
    console.log(
      "🤖 AgentInitializer: Starting autonomous agent initialization..."
    );

    try {
      // Initialize all agents
      const agents = initializeAgents();

      if (agents) {
        console.log("✅ Agents initialized:", Object.keys(agents));

        // Log EventBus status
        const registeredEvents = eventBus.getRegisteredEvents();
        console.log("📡 EventBus events registered:", registeredEvents);

        // Log listener counts
        registeredEvents.forEach((event) => {
          const count = eventBus.getListenerCount(event);
          console.log(`   ${event}: ${count} listener(s)`);
        });

        // Test emit a sample event to verify agents are working
        eventBus.emit("AGENT_ACTION", {
          agent: "System",
          action: "Agents initialized successfully",
          timestamp: new Date(),
        });
      }
    } catch (error) {
      console.error("❌ Agent initialization failed:", error);
    }

    // Cleanup function
    return () => {
      console.log("🔄 AgentInitializer: Cleanup");
    };
  }, []);

  // This component doesn't render anything
  return null;
}
