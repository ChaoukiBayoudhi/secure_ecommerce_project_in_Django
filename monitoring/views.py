"""
Monitoring Dashboard Views.

This module provides views for the admin dashboard showing:
- System health overview
- Real-time metrics
- Alerts and incidents
- AI agent actions
- Historical trends
"""

from django.db.models import Avg, Count, Max, Min, Q
from django.utils import timezone
from datetime import timedelta
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator

from .models import (
    HealthMetric,
    Alert,
    Incident,
    AIAgentAction,
    SystemHealth,
)
from .serializers import (
    HealthMetricSerializer,
    AlertSerializer,
    IncidentSerializer,
    AIAgentActionSerializer,
    SystemHealthSerializer,
    DashboardStatsSerializer,
)
from .ai_agent import AutonomousAIAgent


class DashboardView(APIView):
    """
    Main dashboard view providing comprehensive system overview.
    
    Returns:
    - Current system health
    - Recent alerts
    - Active incidents
    - Recent AI actions
    - Metrics summary
    - Trends
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get dashboard statistics."""
        # Check admin permission
        if not (request.user.is_superuser or request.user.has_role('ADMIN')):
            return Response(
                {'detail': 'Only admins can access the dashboard.'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get current health
        current_health = SystemHealth.objects.first()
        if not current_health:
            # Trigger health check if no snapshot exists
            agent = AutonomousAIAgent()
            agent.monitor_cycle()
            current_health = SystemHealth.objects.first()
        
        # Get recent alerts (last 24 hours)
        recent_alerts = Alert.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).order_by('-created_at')[:10]
        
        # Get active incidents
        active_incidents = Incident.objects.filter(
            status__in=['open', 'investigating']
        ).order_by('-created_at')
        
        # Get recent AI actions (last 24 hours)
        recent_actions = AIAgentAction.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24)
        ).order_by('-created_at')[:10]
        
        # Get metrics summary (last hour)
        one_hour_ago = timezone.now() - timedelta(hours=1)
        metrics_summary = {}
        for metric_type in HealthMetric.objects.values_list('metric_type', flat=True).distinct():
            latest = HealthMetric.objects.filter(
                metric_type=metric_type,
                timestamp__gte=one_hour_ago
            ).order_by('-timestamp').first()
            if latest:
                metrics_summary[metric_type] = {
                    'value': latest.value,
                    'unit': latest.unit,
                    'status': latest.status,
                    'timestamp': latest.timestamp,
                }
        
        # Get trends (last 24 hours)
        trends = self._calculate_trends()
        
        data = {
            'current_health': SystemHealthSerializer(current_health).data if current_health else None,
            'recent_alerts': AlertSerializer(recent_alerts, many=True).data,
            'active_incidents': IncidentSerializer(active_incidents, many=True).data,
            'recent_actions': AIAgentActionSerializer(recent_actions, many=True).data,
            'metrics_summary': metrics_summary,
            'trends': trends,
        }
        
        serializer = DashboardStatsSerializer(data)
        return Response(serializer.data)
    
    def _calculate_trends(self) -> dict:
        """Calculate trends for various metrics."""
        trends = {}
        one_day_ago = timezone.now() - timedelta(days=1)
        
        # CPU trend
        cpu_metrics = HealthMetric.objects.filter(
            metric_type='cpu',
            timestamp__gte=one_day_ago
        ).order_by('timestamp')
        if cpu_metrics.exists():
            last_metric = cpu_metrics.last()
            trends['cpu'] = {
                'current': last_metric.value if last_metric else 0,
                'average': cpu_metrics.aggregate(Avg('value'))['value__avg'] or 0,
                'max': cpu_metrics.aggregate(Max('value'))['value__max'] or 0,
                'min': cpu_metrics.aggregate(Min('value'))['value__min'] or 0,
            }
        
        # Memory trend
        memory_metrics = HealthMetric.objects.filter(
            metric_type='memory',
            timestamp__gte=one_day_ago
        ).order_by('timestamp')
        if memory_metrics.exists():
            last_metric = memory_metrics.last()
            trends['memory'] = {
                'current': last_metric.value if last_metric else 0,
                'average': memory_metrics.aggregate(Avg('value'))['value__avg'] or 0,
                'max': memory_metrics.aggregate(Max('value'))['value__max'] or 0,
                'min': memory_metrics.aggregate(Min('value'))['value__min'] or 0,
            }
        
        # Response time trend
        response_metrics = HealthMetric.objects.filter(
            metric_type='response_time',
            timestamp__gte=one_day_ago
        ).order_by('timestamp')
        if response_metrics.exists():
            last_metric = response_metrics.last()
            trends['response_time'] = {
                'current': last_metric.value if last_metric else 0,
                'average': response_metrics.aggregate(Avg('value'))['value__avg'] or 0,
                'max': response_metrics.aggregate(Max('value'))['value__max'] or 0,
                'min': response_metrics.aggregate(Min('value'))['value__min'] or 0,
            }
        
        # Error rate trend
        error_metrics = HealthMetric.objects.filter(
            metric_type='error_rate',
            timestamp__gte=one_day_ago
        ).order_by('timestamp')
        if error_metrics.exists():
            last_metric = error_metrics.last()
            trends['error_rate'] = {
                'current': last_metric.value if last_metric else 0,
                'average': error_metrics.aggregate(Avg('value'))['value__avg'] or 0,
                'max': error_metrics.aggregate(Max('value'))['value__max'] or 0,
                'min': error_metrics.aggregate(Min('value'))['value__min'] or 0,
            }
        
        return trends


class HealthMetricViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for HealthMetric (read-only)."""
    serializer_class = HealthMetricSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['metric_type', 'status']
    ordering = ['-timestamp']
    
    def get_queryset(self):
        """Filter queryset based on permissions."""
        if not (self.request.user.is_superuser or self.request.user.has_role('ADMIN')):
            return HealthMetric.objects.none()
        return HealthMetric.objects.all()


class AlertViewSet(viewsets.ModelViewSet):
    """ViewSet for Alert management."""
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['alert_type', 'severity', 'status']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Filter queryset based on permissions."""
        if not (self.request.user.is_superuser or self.request.user.has_role('ADMIN')):
            return Alert.objects.none()
        return Alert.objects.all()
    
    @action(detail=True, methods=['post'])
    def acknowledge(self, request, pk=None):
        """Acknowledge an alert."""
        alert = self.get_object()
        alert.status = 'acknowledged'
        alert.acknowledged_at = timezone.now()
        alert.save()
        return Response(AlertSerializer(alert).data)
    
    @action(detail=True, methods=['post'])
    def resolve(self, request, pk=None):
        """Resolve an alert."""
        alert = self.get_object()
        alert.status = 'resolved'
        alert.resolved_at = timezone.now()
        alert.save()
        return Response(AlertSerializer(alert).data)


class IncidentViewSet(viewsets.ModelViewSet):
    """ViewSet for Incident management."""
    serializer_class = IncidentSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['incident_type', 'severity', 'status']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Filter queryset based on permissions."""
        if not (self.request.user.is_superuser or self.request.user.has_role('ADMIN')):
            return Incident.objects.none()
        return Incident.objects.all()


class AIAgentActionViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for AIAgentAction (read-only)."""
    serializer_class = AIAgentActionSerializer
    permission_classes = [IsAuthenticated]
    filterset_fields = ['action_type', 'status']
    ordering = ['-created_at']
    
    def get_queryset(self):
        """Filter queryset based on permissions."""
        if not (self.request.user.is_superuser or self.request.user.has_role('ADMIN')):
            return AIAgentAction.objects.none()
        return AIAgentAction.objects.all()
    
    @action(detail=False, methods=['post'])
    def trigger_monitoring(self, request):
        """Manually trigger a monitoring cycle."""
        agent = AutonomousAIAgent()
        results = agent.monitor_cycle()
        return Response({
            'message': 'Monitoring cycle completed',
            'results': results,
        })


class SystemHealthViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for SystemHealth (read-only)."""
    serializer_class = SystemHealthSerializer
    permission_classes = [IsAuthenticated]
    ordering = ['-timestamp']
    
    def get_queryset(self):
        """Filter queryset based on permissions."""
        if not (self.request.user.is_superuser or self.request.user.has_role('ADMIN')):
            return SystemHealth.objects.none()
        return SystemHealth.objects.all()


def dashboard_html(request):
    """
    Render HTML dashboard page.
    
    This view serves the HTML dashboard interface.
    """
    if not request.user.is_authenticated:
        from django.contrib.auth.views import redirect_to_login
        return redirect_to_login(request.get_full_path())
    
    if not (request.user.is_superuser or request.user.has_role('ADMIN')):
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden("Only admins can access the dashboard.")
    
    return render(request, 'monitoring/dashboard.html')
