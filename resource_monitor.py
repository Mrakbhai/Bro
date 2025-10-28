import psutil
import os

RAM_THRESHOLD_MB = 600
RAM_PERCENT_THRESHOLD = 72
SWAP_THRESHOLD_MB = 200
LOAD_THRESHOLD = 2.0
DISK_FREE_GB_MIN = 1.0
MAX_CONCURRENT_DOWNLOADS = 2

class ResourceMonitor:
    """Monitor system resources and determine if processing can proceed"""
    
    @staticmethod
    def get_system_status():
        """Get current system resource status"""
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        disk = psutil.disk_usage('/')
        
        try:
            load_avg = psutil.getloadavg()[0]
        except (AttributeError, OSError):
            load_avg = 0.0
        
        return {
            'mem_available_mb': mem.available / (1024 * 1024),
            'mem_percent': mem.percent,
            'mem_total_mb': mem.total / (1024 * 1024),
            'mem_used_mb': mem.used / (1024 * 1024),
            'swap_used_mb': swap.used / (1024 * 1024),
            'swap_percent': swap.percent,
            'disk_free_gb': disk.free / (1024 * 1024 * 1024),
            'disk_total_gb': disk.total / (1024 * 1024 * 1024),
            'disk_percent': disk.percent,
            'load_1min': load_avg,
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'cpu_count': psutil.cpu_count()
        }
    
    @staticmethod
    def can_process(file_size_bytes=0):
        """
        Check if system has enough resources to process a job
        
        Args:
            file_size_bytes: Size of file to process (for disk space check)
        
        Returns:
            (can_process: bool, reason: str or None)
        """
        status = ResourceMonitor.get_system_status()
        
        if status['mem_available_mb'] < RAM_THRESHOLD_MB:
            return False, f"Low RAM ({status['mem_available_mb']:.0f} MB available, need {RAM_THRESHOLD_MB} MB)"
        
        if status['mem_percent'] > RAM_PERCENT_THRESHOLD:
            return False, f"High RAM usage ({status['mem_percent']:.1f}%, threshold {RAM_PERCENT_THRESHOLD}%)"
        
        if status['swap_used_mb'] > SWAP_THRESHOLD_MB:
            return False, f"High swap usage ({status['swap_used_mb']:.0f} MB, threshold {SWAP_THRESHOLD_MB} MB)"
        
        if status['load_1min'] > LOAD_THRESHOLD:
            return False, f"High system load ({status['load_1min']:.2f}, threshold {LOAD_THRESHOLD})"
        
        file_size_gb = file_size_bytes / (1024 * 1024 * 1024)
        disk_needed_gb = file_size_gb * 2 + DISK_FREE_GB_MIN
        
        if status['disk_free_gb'] < disk_needed_gb:
            return False, f"Insufficient disk space ({status['disk_free_gb']:.1f} GB free, need {disk_needed_gb:.1f} GB)"
        
        return True, None
    
    @staticmethod
    def get_resource_message(file_size_bytes=0):
        """Get a user-friendly message about resource status"""
        can_process, reason = ResourceMonitor.can_process(file_size_bytes)
        
        if can_process:
            return None
        
        status = ResourceMonitor.get_system_status()
        
        if "RAM" in reason or "swap" in reason:
            return f"Processing delayed: server RAM is high ({status['mem_percent']:.0f}%). Your file is queued and will be processed automatically when resources are available."
        elif "load" in reason:
            return f"Processing delayed: server is busy (CPU load {status['load_1min']:.1f}). Your file will be processed automatically when the server is less busy."
        elif "disk" in reason:
            return f"Insufficient storage space. {status['disk_free_gb']:.1f} GB available. Please contact administrator or try a smaller file."
        else:
            return f"Processing delayed: {reason}. Your file will be processed automatically when resources are available."
    
    @staticmethod
    def estimate_processing_time(file_size_bytes, video_duration_seconds=None):
        """
        Estimate processing time for a file
        
        Args:
            file_size_bytes: Size of file in bytes
            video_duration_seconds: Video duration if known
        
        Returns:
            Estimated seconds to process
        """
        file_size_gb = file_size_bytes / (1024 * 1024 * 1024)
        
        base_time_per_gb = 5 * 60
        
        status = ResourceMonitor.get_system_status()
        
        if status['cpu_count'] and status['cpu_count'] <= 2:
            base_time_per_gb *= 1.5
        
        if status['mem_percent'] > 60:
            base_time_per_gb *= 1.3
        
        estimated_seconds = int(file_size_gb * base_time_per_gb)
        
        return max(estimated_seconds, 30)

if __name__ == '__main__':
    monitor = ResourceMonitor()
    status = monitor.get_system_status()
    
    print("System Resource Status:")
    print(f"  RAM: {status['mem_used_mb']:.0f} MB / {status['mem_total_mb']:.0f} MB ({status['mem_percent']:.1f}% used)")
    print(f"  RAM Available: {status['mem_available_mb']:.0f} MB")
    print(f"  Swap: {status['swap_used_mb']:.0f} MB ({status['swap_percent']:.1f}% used)")
    print(f"  Disk: {status['disk_free_gb']:.1f} GB / {status['disk_total_gb']:.1f} GB free ({status['disk_percent']:.1f}% used)")
    print(f"  Load (1 min): {status['load_1min']:.2f}")
    print(f"  CPU: {status['cpu_percent']:.1f}%")
    print(f"  CPU Cores: {status['cpu_count']}")
    
    print("\nCan process? ", monitor.can_process(100 * 1024 * 1024))
    
    print("\nEstimated processing time for 500MB file:", 
          f"{monitor.estimate_processing_time(500 * 1024 * 1024) // 60} minutes")
