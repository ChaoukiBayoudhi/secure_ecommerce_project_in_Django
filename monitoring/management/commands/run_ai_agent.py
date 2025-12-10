"""
Management command to run the autonomous AI agent for health monitoring.

Usage:
    python manage.py run_ai_agent

This command runs the AI agent continuously, monitoring the application
and taking autonomous actions to maintain health.
"""

import time
import signal
import sys
from django.core.management.base import BaseCommand
from monitoring.ai_agent import AutonomousAIAgent


class Command(BaseCommand):
    help = 'Run the autonomous AI agent for health monitoring'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=30,
            help='Monitoring interval in seconds (default: 30)',
        )
        parser.add_argument(
            '--once',
            action='store_true',
            help='Run monitoring cycle once and exit',
        )
    
    def handle(self, *args, **options):
        """Run the AI agent."""
        agent = AutonomousAIAgent()
        agent.monitoring_interval = options['interval']
        
        if options['once']:
            # Run once and exit
            self.stdout.write('Running monitoring cycle...')
            results = agent.monitor_cycle()
            self.stdout.write(
                self.style.SUCCESS(
                    f'Monitoring cycle completed. Status: {results.get("overall_status", "unknown")}'
                )
            )
            return
        
        # Run continuously
        self.stdout.write(
            self.style.SUCCESS(
                f'Starting AI agent with {agent.monitoring_interval}s interval...'
            )
        )
        self.stdout.write('Press Ctrl+C to stop')
        
        # Handle graceful shutdown
        def signal_handler(sig, frame):
            self.stdout.write(self.style.WARNING('\nShutting down AI agent...'))
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        cycle_count = 0
        try:
            while True:
                cycle_count += 1
                self.stdout.write(f'\n[{cycle_count}] Running monitoring cycle...')
                
                results = agent.monitor_cycle()
                
                status = results.get('overall_status', 'unknown')
                if status == 'critical':
                    self.stdout.write(
                        self.style.ERROR(f'Status: {status.upper()} - {results.get("alerts_generated", 0)} alerts generated')
                    )
                elif status == 'warning':
                    self.stdout.write(
                        self.style.WARNING(f'Status: {status.upper()} - {results.get("alerts_generated", 0)} alerts generated')
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(f'Status: {status.upper()} - System healthy')
                    )
                
                if results.get('actions_taken', 0) > 0:
                    self.stdout.write(
                        self.style.SUCCESS(f'AI Agent took {results["actions_taken"]} autonomous action(s)')
                    )
                
                # Wait for next cycle
                time.sleep(agent.monitoring_interval)
        
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('\nShutting down AI agent...'))
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error in AI agent: {e}')
            )
            raise

