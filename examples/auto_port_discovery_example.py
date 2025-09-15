#!/usr/bin/env python3
"""
Example demonstrating intelligent Diameter port auto-discovery.

This example shows how the Pcap class can automatically identify which ports
contain Diameter traffic, eliminating the need for manual port specification
in telecom environments with varying configurations.

Author: Fabio Bilotto (Amdocs)
Performance-optimized for telecom BSS/OSS environments
"""

import os
import sys
from pathlib import Path

# Add the src directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    from diameter_parse_pcap import Pcap, DiameterPortConstants
    print("✅ Successfully imported diameter_parse_pcap")
except ImportError as e:
    print(f"❌ Failed to import diameter_parse_pcap: {e}")
    print("Please ensure the library is properly installed")
    sys.exit(1)


def demonstrate_auto_discovery():
    """
    Demonstrate the intelligent port auto-discovery feature.
    """
    print("=== Diameter Port Auto-Discovery Demo ===")
    print("Performance-optimized for telecom environments\n")
    
    # Look for sample PCAP files
    sample_paths = [
        "pcap_samples",
        "../pcap_samples", 
        "../../pcap_samples"
    ]
    
    sample_files = []
    for path in sample_paths:
        if Path(path).exists():
            pcap_files = list(Path(path).rglob("*.pcap*"))
            sample_files.extend(pcap_files)
            break
    
    if not sample_files:
        print("⚠️  No PCAP sample files found")
        print("📁 Please place PCAP files in:")
        for path in sample_paths:
            print(f"   • {path}")
        print("\n💡 Creating example with manual PCAP path...")
        demonstrate_manual_path()
        return
    
    print(f"🔍 Found {len(sample_files)} PCAP files for analysis\n")
    
    # Analyze each PCAP file
    for i, pcap_path in enumerate(sample_files[:3], 1):  # Limit to first 3 for demo
        print(f"📊 Analysis {i}: {pcap_path.name}")
        print("-" * 50)
        
        try:
            # Method 1: Auto-discovery (no ports specified)
            print("🤖 Method 1: Automatic Port Discovery")
            pcap_auto = Pcap(filepath=str(pcap_path))  # No ports specified!
            
            if pcap_auto.is_ports_auto_discovered:
                print(f"✅ Auto-discovered ports: {pcap_auto.ports}")
                
                # Show telecom context for discovered ports
                for port in pcap_auto.ports:
                    if port in DiameterPortConstants.PORT_MAPPINGS:
                        app_name = DiameterPortConstants.PORT_MAPPINGS[port]
                        print(f"   📡 Port {port}: {app_name}")
                    else:
                        print(f"   🔍 Port {port}: Custom/Unknown application")
            else:
                print(f"   ⚙️  Used manually specified ports: {pcap_auto.ports}")
            
            # Get basic statistics
            pcap_auto.get_timestamps()
            print(f"   💬 Messages found: {pcap_auto.n_diameter_messages}")
            if pcap_auto.start_timestamp and pcap_auto.end_timestamp:
                duration = pcap_auto.end_timestamp - pcap_auto.start_timestamp
                print(f"   ⏱️  Duration: {duration:.1f} seconds")
            
            print()
            
            # Method 2: Manual port specification for comparison
            print("⚙️  Method 2: Manual Port Specification (comparison)")
            manual_ports = [3868, 3869, 3009, 3019]
            pcap_manual = Pcap(
                filepath=str(pcap_path),
                ports=manual_ports,
                filter="diameter"
            )
            
            pcap_manual.get_timestamps()
            print(f"   🔧 Manual ports: {manual_ports}")
            print(f"   💬 Messages found: {pcap_manual.n_diameter_messages}")
            
            # Performance comparison
            auto_msg_count = pcap_auto.n_diameter_messages
            manual_msg_count = pcap_manual.n_diameter_messages
            
            if auto_msg_count > manual_msg_count:
                improvement = auto_msg_count - manual_msg_count
                print(f"   🎯 Auto-discovery found {improvement} more messages!")
            elif auto_msg_count == manual_msg_count:
                print(f"   ✅ Both methods found same number of messages")
            else:
                diff = manual_msg_count - auto_msg_count
                print(f"   ⚠️  Manual ports found {diff} more messages")
                
        except Exception as e:
            print(f"   ❌ Error analyzing {pcap_path.name}: {e}")
            
        print("\n" + "="*60 + "\n")


def demonstrate_manual_path():
    """
    Demonstrate port discovery with a manually specified PCAP file.
    """
    print("📝 Manual PCAP Path Demo")
    print("You can test port auto-discovery with any PCAP file:\n")
    
    example_code = '''
# Example: Auto-discovery with your PCAP file
from diameter_parse_pcap import Pcap

# Just specify the file path - ports will be auto-discovered!
pcap = Pcap(filepath="/path/to/your/file.pcap")

# The library will automatically:
# 1. Test standard telecom ports (3868, 3869, 3009, 3019, etc.)
# 2. If none found, scan all ports in the PCAP
# 3. Validate Diameter signatures in the traffic
# 4. Return ordered list by telecom relevance

print(f"Auto-discovered ports: {pcap.ports}")
print(f"Were ports auto-discovered? {pcap.is_ports_auto_discovered}")

# Get message statistics
pcap.get_timestamps()
print(f"Diameter messages: {pcap.n_diameter_messages}")
'''
    
    print(example_code)
    
    print("🔧 Performance Features:")
    print("  • Prioritizes standard telecom ports for speed")
    print("  • Limits packet analysis to avoid performance impact")
    print("  • Uses protocol signature detection for accuracy")
    print("  • Falls back gracefully if auto-discovery fails")
    print("  • Caches results for repeated analysis")


def show_port_constants():
    """
    Display the comprehensive telecom port constants used for discovery.
    """
    print("📡 Telecom Port Knowledge Base")
    print("=" * 40)
    
    print("\n🎯 Standard Discovery Ports (checked first):")
    for port in DiameterPortConstants.STANDARD_PORTS:
        if port in DiameterPortConstants.PORT_MAPPINGS:
            print(f"  • {port}: {DiameterPortConstants.PORT_MAPPINGS[port]}")
        else:
            print(f"  • {port}: Standard telecom port")
    
    print("\n🌐 Complete Application Mappings:")
    for port, desc in sorted(DiameterPortConstants.PORT_MAPPINGS.items()):
        print(f"  • {port}: {desc}")
    
    print("\n📊 Application ID → Port Mappings:")
    for app_id, ports in DiameterPortConstants.APP_ID_PORTS.items():
        app_name = {
            0: "Base Protocol",
            4: "Gy Credit Control",
            16777238: "Gx Policy Control", 
            16777236: "Rx Media Plane",
            16777302: "Sy Spending Limits",
            16777251: "S6a Authentication"
        }.get(app_id, f"App {app_id}")
        
        print(f"  • {app_name} ({app_id}): {ports}")
    
    print(f"\n🔍 Port Ranges Analyzed:")
    for start, end in DiameterPortConstants.COMMON_RANGES:
        print(f"  • {start}-{end}: {'Standard Diameter' if start == 3000 else 'Extended telecom' if start == 30000 else 'Alternative'} range")


def main():
    """Main execution function."""
    print("🚀 Diameter Port Auto-Discovery Examples")
    print("Intelligent port identification for telecom PCAP analysis\n")
    
    try:
        # Show the comprehensive port knowledge base
        show_port_constants()
        print("\n")
        
        # Demonstrate auto-discovery
        demonstrate_auto_discovery()
        
        print("\n💡 Key Benefits:")
        print("  ✅ No need to specify ports manually")
        print("  ✅ Adapts to different network configurations")  
        print("  ✅ Performance-optimized for telecom scale")
        print("  ✅ Comprehensive 3GPP application support")
        print("  ✅ Graceful fallback for unknown scenarios")
        
        print("\n🎯 Perfect for:")
        print("  • Multi-vendor telecom environments")
        print("  • Unknown or varying port configurations")
        print("  • Automated PCAP analysis pipelines")
        print("  • BSS/OSS operational workflows")
        
    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        print("\n🔧 Troubleshooting:")
        print("  • Ensure PCAP files contain Diameter traffic")
        print("  • Check that tshark/Wireshark is installed")
        print("  • Verify file permissions and accessibility")


if __name__ == "__main__":
    main()
