"""
Monitoring Middleware for tracking response times and errors.

This middleware tracks API performance metrics for the monitoring system.
"""

import time
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from datetime import timedelta


class MonitoringMiddleware(MiddlewareMixin):
    """
    Middleware to track API performance metrics.
    
    Tracks:
    - Response times
    - Error rates
    - Request throughput
    """
    
    def process_request(self, request):
        """Record request start time."""
        if request.path.startswith('/api/'):
            request._monitoring_start_time = time.time()
        return None
    
    def process_response(self, request, response):
        """Record response metrics."""
        if hasattr(request, '_monitoring_start_time'):
            # Calculate response time
            response_time = (time.time() - request._monitoring_start_time) * 1000  # Convert to ms
            
            # Track response time
            self._track_response_time(response_time)
            
            # Track error rate
            if response.status_code >= 400:
                self._track_error()
            else:
                self._track_success()
            
            # Track throughput
            self._track_throughput()
        
        return response
    
    def _track_response_time(self, response_time):
        """Track average response time."""
        cache_key = 'avg_response_time'
        current_avg = cache.get(cache_key, 0.0) or 0.0
        
        # Simple moving average (exponential smoothing)
        new_avg = (current_avg * 0.9) + (response_time * 0.1)
        cache.set(cache_key, new_avg, timeout=3600)
    
    def _track_error(self):
        """Track error occurrence."""
        cache_key = 'error_count'
        error_count = cache.get(cache_key, 0) or 0
        cache.set(cache_key, error_count + 1, timeout=3600)
        
        # Calculate error rate
        total_requests = cache.get('total_requests', 0) or 0
        if total_requests > 0:
            error_rate = (error_count / total_requests) * 100
            cache.set('error_rate', error_rate, timeout=3600)
    
    def _track_success(self):
        """Track successful request."""
        cache_key = 'success_count'
        success_count = cache.get(cache_key, 0) or 0
        cache.set(cache_key, success_count + 1, timeout=3600)
    
    def _track_throughput(self):
        """Track request throughput."""
        cache_key = 'total_requests'
        total_requests = cache.get(cache_key, 0) or 0
        cache.set(cache_key, total_requests + 1, timeout=3600)
        
        # Calculate throughput (requests per second)
        now = timezone.now()
        minute_key = f'requests_minute_{now.minute}'
        minute_count = cache.get(minute_key, 0) or 0
        cache.set(minute_key, minute_count + 1, timeout=60)
        
        # Average over last minute
        throughput = minute_count / 60.0  # requests per second
        cache.set('throughput', throughput, timeout=60)

