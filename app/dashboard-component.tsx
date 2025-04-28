import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { AlertTriangle, Shield, ShieldCheck, Clock } from 'lucide-react';

const COLORS = {
  Critical: '#FF4444',
  High: '#FFA500',
  Medium: '#FFCC00',
  Low: '#AAAAAA',
  Negligible: '#DDDDDD',
  Unknown: '#999999',
};

const VulnerabilityDashboard = () => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch('/status');
        if (!response.ok) {
          throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const result = await response.json();
        setData(result);
        setLoading(false);
      } catch (err) {
        setError(err.message);
        setLoading(false);
      }
    };

    fetchData();
    // Refresh data every 5 minutes
    const interval = setInterval(fetchData, 300000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <Clock className="w-12 h-12 mx-auto text-blue-500 animate-spin" />
          <p className="mt-4 text-lg">Loading vulnerability data...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-center">
          <AlertTriangle className="w-12 h-12 mx-auto text-red-500" />
          <p className="mt-4 text-lg">Error loading data: {error}</p>
        </div>
      </div>
    );
  }

  // Format data for the severity chart
  const severityData = Object.entries(data.severity_distribution || {}).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value,
  }));

  // Format data for the top packages chart
  const packageData = Object.entries(data.top_vulnerable_packages || {}).map(([name, value]) => ({
    name: name.length > 15 ? name.substring(0, 12) + '...' : name,
    vulnerabilities: value,
    fullName: name,
  }));

  const formatDate = (timestamp) => {
    if (!timestamp || timestamp === 'unknown') return 'Unknown';
    try {
      return new Date(timestamp).toLocaleString();
    } catch (e) {
      return timestamp;
    }
  };

  const hasCriticalOrHigh = severityData.some(item => 
    item.name === 'Critical' && item.value > 0 || 
    item.name === 'High' && item.value > 0
  );

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900">Vulnerability Scan Dashboard</h1>
        <p className="text-gray-600">
          Last scan: {formatDate(data.scan_timestamp || data.scan_time)}
        </p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* Total Vulnerabilities Card */}
        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-sm">Total Vulnerabilities</p>
              <p className="text-3xl font-bold">{data.total_vulnerabilities}</p>
            </div>
            <AlertTriangle className="w-10 h-10 text-blue-500" />
          </div>
        </div>

        {/* Critical/High Vulnerabilities Card */}
        <div className={`p-6 rounded-lg shadow ${hasCriticalOrHigh ? 'bg-red-50' : 'bg-green-50'}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-sm">Critical/High Vulnerabilities</p>
              <p className="text-3xl font-bold">
                {(data.severity_distribution?.Critical || 0) + (data.severity_distribution?.High || 0)}
              </p>
            </div>
            {hasCriticalOrHigh ? (
              <Shield className="w-10 h-10 text-red-500" />
            ) : (
              <ShieldCheck className="w-10 h-10 text-green-500" />
            )}
          </div>
        </div>

        {/* Fixable Vulnerabilities Card */}
        <div className="bg-white p-6 rounded-lg shadow">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-500 text-sm">Fixable Vulnerabilities</p>
              <p className="text-3xl font-bold">{data.fixable_vulnerabilities || 'N/A'}</p>
            </div>
            <div className="w-10 h-10 flex items-center justify-center rounded-full bg-yellow-100">
              <span className="text-yellow-600 text-xl">⚙️</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
        {/* Severity Distribution Chart */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-4">Vulnerability Severity Distribution</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[entry.name] || '#999999'} />
                  ))}
                </Pie>
                <Tooltip formatter={(value) => [`${value} vulnerabilities`, 'Count']} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Vulnerable Packages Chart */}
        <div className="bg-white p-6 rounded-lg shadow">
          <h2 className="text-xl font-semibold mb-4">Top Vulnerable Packages</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={packageData}
                margin={{ top: 5, right: 30, left: 20, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip 
                  formatter={(value, name, props) => [value, 'Vulnerabilities']}
                  labelFormatter={(value) => packageData.find(item => item.name === value)?.fullName || value}
                />
                <Legend />
                <Bar dataKey="vulnerabilities" fill="#8884d8" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="bg-blue-50 p-6 rounded-lg shadow">
        <h2 className="text-xl font-semibold mb-2">Security Recommendation</h2>
        <p className="text-gray-700">
          {hasCriticalOrHigh ? 
            "Critical or high severity vulnerabilities have been detected. Immediate action is recommended to address these issues." : 
            "No critical or high severity vulnerabilities detected. Continue regular scanning and monitoring to maintain security."
          }
        </p>
        <div className="mt-4">
          <a 
            href="/scan" 
            className="inline-block bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
          >
            View Detailed Report
          </a>
        </div>
      </div>
    </div>
  );
};

export default VulnerabilityDashboard;
