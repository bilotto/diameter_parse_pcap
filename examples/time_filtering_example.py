#!/usr/bin/env python3
"""
Example demonstrating time-based PCAP filtering capabilities.

This example shows how to filter PCAP files by various time criteria:
- Time range filtering
- Date-based filtering  
- Hour range filtering
- Combined filtering strategies

Author: Fabio Bilotto (Amdocs)
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add the src directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from diameter_parse_pcap import PcapGroup
    print("✅ Successfully imported diameter_parse_pcap")
except ImportError as e:
    print(f"❌ Failed to import diameter_parse_pcap: {e}")
    print("Please ensure the library is properly installed")
    sys.exit(1)


def demonstrate_time_filtering():
    """
    Demonstrate various time-based filtering capabilities.
    """
    print("=== Time-Based PCAP Filtering Demo ===")
    print("Advanced datetime filtering for telecom PCAP analysis\n")
    
    # Look for sample PCAP files
    sample_paths = [
        "pcap_samples",
        "../pcap_samples", 
        "../../pcap_samples"
    ]
    
    sample_dir = None
    for path in sample_paths:
        if Path(path).exists():
            sample_dir = path
            break
    
    if not sample_dir:
        print("⚠️  No PCAP sample directory found")
        print("📁 Please place PCAP files in one of these directories:")
        for path in sample_paths:
            print(f"   • {path}")
        print("\n💡 Creating example with manual directory path...")
        demonstrate_manual_filtering()
        return
    
    print(f"🔍 Using sample directory: {sample_dir}\n")
    
    try:
        # Create PcapGroup
        pcap_group = PcapGroup(
            directory=sample_dir,
            name_pattern=r".*\.pcap.*"
        )
        
        if not pcap_group.pcaps:
            print("❌ No PCAP files found in the directory")
            return
            
        print(f"📊 Loaded {len(pcap_group.pcaps)} PCAP files")
        
        # Show time range of all PCAPs
        if pcap_group.pcaps:
            start_times = [pcap.start_timestamp for pcap in pcap_group.pcaps if pcap.start_timestamp]
            end_times = [pcap.end_timestamp for pcap in pcap_group.pcaps if pcap.end_timestamp]
            
            if start_times and end_times:
                earliest = datetime.fromtimestamp(min(start_times))
                latest = datetime.fromtimestamp(max(end_times))
                print(f"⏰ Time range: {earliest.strftime('%Y-%m-%d %H:%M:%S')} to {latest.strftime('%Y-%m-%d %H:%M:%S')}")
                print()
        
        # Example 1: Filter by time range
        print("🕐 Example 1: Time Range Filtering")
        print("-" * 40)
        
        # Get PCAPs from the last 2 hours of the time range
        if start_times and end_times:
            latest_time = datetime.fromtimestamp(max(end_times))
            two_hours_ago = latest_time - timedelta(hours=2)
            
            recent_pcaps = pcap_group.get_pcaps_by_time_range(two_hours_ago, latest_time)
            print(f"📊 PCAPs from last 2 hours: {len(recent_pcaps)} files")
            
            for pcap in recent_pcaps[:3]:  # Show first 3
                start_dt = datetime.fromtimestamp(pcap.start_timestamp) if pcap.start_timestamp else None
                end_dt = datetime.fromtimestamp(pcap.end_timestamp) if pcap.end_timestamp else None
                if start_dt and end_dt:
                    print(f"   • {pcap.filename}: {start_dt.strftime('%H:%M:%S')} - {end_dt.strftime('%H:%M:%S')}")
        
        print()
        
        # Example 2: Filter by specific date
        print("📅 Example 2: Date-Based Filtering")
        print("-" * 40)
        
        if start_times:
            # Get PCAPs from the first date found
            first_date = datetime.fromtimestamp(min(start_times)).date()
            target_datetime = datetime.combine(first_date, datetime.min.time())
            
            date_pcaps = pcap_group.get_pcaps_by_date(target_datetime)
            print(f"📊 PCAPs from {first_date}: {len(date_pcaps)} files")
            
            for pcap in date_pcaps[:3]:  # Show first 3
                start_dt = datetime.fromtimestamp(pcap.start_timestamp) if pcap.start_timestamp else None
                if start_dt:
                    print(f"   • {pcap.filename}: {start_dt.strftime('%H:%M:%S')}")
        
        print()
        
        # Example 3: Filter by hour range
        print("🕒 Example 3: Hour Range Filtering")
        print("-" * 40)
        
        # Get PCAPs from business hours (9 AM to 5 PM)
        business_hour_pcaps = pcap_group.get_pcaps_by_hour_range(9, 17, target_datetime)
        print(f"📊 PCAPs from business hours (9 AM - 5 PM): {len(business_hour_pcaps)} files")
        
        for pcap in business_hour_pcaps[:3]:  # Show first 3
            start_dt = datetime.fromtimestamp(pcap.start_timestamp) if pcap.start_timestamp else None
            if start_dt:
                print(f"   • {pcap.filename}: {start_dt.strftime('%H:%M:%S')}")
        
        print()
        
        # Example 4: Combined filtering
        print("🔗 Example 4: Combined Filtering")
        print("-" * 40)
        
        # Get PCAPs from business hours on the first date
        if start_times:
            first_date = datetime.fromtimestamp(min(start_times)).date()
            target_datetime = datetime.combine(first_date, datetime.min.time())
            
            # Business hours on specific date
            business_pcaps = pcap_group.get_pcaps_by_hour_range(9, 17, target_datetime)
            
            # Filter by name pattern (e.g., files containing "gx")
            gx_pcaps = pcap_group.get_pcaps_by_name_pattern(r".*gx.*")
            
            print(f"📊 Business hours PCAPs: {len(business_pcaps)} files")
            print(f"📊 Gx-related PCAPs: {len(gx_pcaps)} files")
            
            # Find intersection
            business_gx_pcaps = [pcap for pcap in business_pcaps if pcap in gx_pcaps]
            print(f"📊 Business hours + Gx PCAPs: {len(business_gx_pcaps)} files")
        
        print()
        
        # Example 5: Performance comparison
        print("⚡ Example 5: Performance Comparison")
        print("-" * 40)
        
        import time
        
        # Time the filtering operations
        start_time = time.time()
        all_pcaps = pcap_group.pcaps
        load_time = time.time() - start_time
        
        start_time = time.time()
        recent_pcaps = pcap_group.get_pcaps_by_time_range(two_hours_ago, latest_time)
        filter_time = time.time() - start_time
        
        print(f"📊 Load all PCAPs: {load_time:.3f} seconds")
        print(f"📊 Filter by time range: {filter_time:.3f} seconds")
        print(f"📊 Filter efficiency: {len(recent_pcaps)}/{len(all_pcaps)} files ({len(recent_pcaps)/len(all_pcaps)*100:.1f}%)")
        
    except Exception as e:
        print(f"❌ Error during filtering demo: {e}")


def demonstrate_manual_filtering():
    """
    Demonstrate filtering with manually specified directory.
    """
    print("📝 Manual Time Filtering Demo")
    print("You can use time filtering with any PCAP directory:\n")
    
    example_code = '''
# Example: Time-based PCAP filtering
from diameter_parse_pcap import PcapGroup
from datetime import datetime, timedelta

# Create PcapGroup
pcap_group = PcapGroup(
    directory="/path/to/your/pcaps",
    name_pattern=r".*\.pcap.*"
)

# Filter by time range
start_time = datetime(2024, 1, 15, 9, 0, 0)  # 9 AM
end_time = datetime(2024, 1, 15, 17, 0, 0)   # 5 PM
business_pcaps = pcap_group.get_pcaps_by_time_range(start_time, end_time)

# Filter by specific date
target_date = datetime(2024, 1, 15)
date_pcaps = pcap_group.get_pcaps_by_date(target_date)

# Filter by hour range (business hours)
hour_pcaps = pcap_group.get_pcaps_by_hour_range(9, 17, target_date)

# Filter by name pattern
gx_pcaps = pcap_group.get_pcaps_by_name_pattern(r".*gx.*")

print(f"Business hours PCAPs: {len(business_pcaps)}")
print(f"Date PCAPs: {len(date_pcaps)}")
print(f"Hour range PCAPs: {len(hour_pcaps)}")
print(f"Gx PCAPs: {len(gx_pcaps)}")
'''
    
    print(example_code)
    
    print("🔧 Time Filtering Features:")
    print("  • Time range filtering with datetime objects")
    print("  • Date-based filtering (entire day)")
    print("  • Hour range filtering (specific hours)")
    print("  • Name pattern filtering (regex)")
    print("  • Combined filtering strategies")
    print("  • Performance optimized for large PCAP collections")


def show_filtering_methods():
    """
    Display all available filtering methods.
    """
    print("📋 Available Filtering Methods")
    print("=" * 40)
    
    methods = [
        ("get_pcaps_by_time_range(start, end)", "Filter by datetime range"),
        ("get_pcaps_by_date(target_date)", "Filter by specific date"),
        ("get_pcaps_by_hour_range(start_hour, end_hour, date)", "Filter by hour range"),
        ("get_pcaps_by_name_pattern(regex)", "Filter by filename pattern"),
    ]
    
    for method, description in methods:
        print(f"  • {method}")
        print(f"    {description}")
        print()


def main():
    """Main execution function."""
    print("🚀 Diameter PCAP Time Filtering Examples")
    print("Advanced datetime filtering for telecom analysis\n")
    
    try:
        # Show available methods
        show_filtering_methods()
        
        # Demonstrate filtering
        demonstrate_time_filtering()
        
        print("\n💡 Key Benefits:")
        print("  ✅ Precise time-based filtering")
        print("  ✅ Multiple filtering strategies")
        print("  ✅ Performance optimized")
        print("  ✅ Easy to combine filters")
        print("  ✅ Telecom-focused time ranges")
        
        print("\n🎯 Perfect for:")
        print("  • Business hours analysis")
        print("  • Incident time window analysis")
        print("  • Daily/weekly reporting")
        print("  • Peak traffic analysis")
        print("  • Multi-timezone environments")
        
    except KeyboardInterrupt:
        print("\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("\n🔧 Troubleshooting:")
        print("  • Ensure PCAP files contain valid timestamps")
        print("  • Check that datetime objects are properly formatted")
        print("  • Verify PCAP files are accessible")


if __name__ == "__main__":
    main()
