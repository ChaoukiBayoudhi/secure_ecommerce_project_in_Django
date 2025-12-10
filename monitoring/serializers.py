"""
Monitoring Serializers for Dashboard API.
"""

from rest_framework import serializers
from .models import (
    HealthMetric,
    Alert,
    Incident,
    AIAgentAction,
    SystemHealth,
)


class HealthMetricSerializer(serializers.ModelSerializer):
    """Serializer for HealthMetric."""
    
    class Meta:
        model = HealthMetric
        fields = [
            'id',
            'metric_type',
            'value',
            'unit',
            'warning_threshold',
            'critical_threshold',
            'status',
            'metadata',
            'timestamp',
        ]


class AlertSerializer(serializers.ModelSerializer):
    """Serializer for Alert."""
    
    class Meta:
        model = Alert
        fields = [
            'id',
            'alert_type',
            'severity',
            'title',
            'message',
            'source',
            'status',
            'ai_action_taken',
            'ai_action_description',
            'metadata',
            'created_at',
            'acknowledged_at',
            'resolved_at',
        ]


class IncidentSerializer(serializers.ModelSerializer):
    """Serializer for Incident."""
    
    class Meta:
        model = Incident
        fields = [
            'id',
            'title',
            'description',
            'incident_type',
            'severity',
            'status',
            'ai_detected',
            'ai_resolved',
            'ai_actions',
            'resolution',
            'metadata',
            'created_at',
            'resolved_at',
            'closed_at',
        ]


class AIAgentActionSerializer(serializers.ModelSerializer):
    """Serializer for AIAgentAction."""
    
    class Meta:
        model = AIAgentAction
        fields = [
            'id',
            'action_type',
            'description',
            'triggered_by',
            'status',
            'success',
            'result_message',
            'metadata',
            'created_at',
            'executed_at',
            'completed_at',
        ]


class SystemHealthSerializer(serializers.ModelSerializer):
    """Serializer for SystemHealth."""
    
    class Meta:
        model = SystemHealth
        fields = [
            'id',
            'overall_status',
            'api_status',
            'database_status',
            'cache_status',
            'cpu_usage',
            'memory_usage',
            'disk_usage',
            'avg_response_time',
            'error_rate',
            'active_alerts_count',
            'critical_alerts_count',
            'active_incidents_count',
            'metadata',
            'timestamp',
        ]


class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for dashboard statistics."""
    
    current_health = SystemHealthSerializer()
    recent_alerts = AlertSerializer(many=True)
    active_incidents = IncidentSerializer(many=True)
    recent_actions = AIAgentActionSerializer(many=True)
    metrics_summary = serializers.DictField()
    trends = serializers.DictField()

