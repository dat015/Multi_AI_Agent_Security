import React from 'react';
import { Activity, ShieldAlert, ShieldCheck, Percent } from 'lucide-react';
import { cn } from '../../../lib/utils';

interface SummaryCardsProps {
  total: number;
  vulnerable: number;
  safe: number;
  ratio: string;
}

const SummaryCards: React.FC<SummaryCardsProps> = ({ total, vulnerable, safe, ratio }) => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      <Card
        title="Tổng số API đã test"
        value={total.toString()}
        icon={<Activity size={24} className="text-blue-400" />}
      />
      <Card
        title="Số lỗ hổng phát hiện"
        value={vulnerable.toString()}
        icon={<ShieldAlert size={24} className="text-red-500" />}
        valueClassName="text-red-500"
        trend="High priority"
      />
      <Card
        title="Số API an toàn"
        value={safe.toString()}
        icon={<ShieldCheck size={24} className="text-green-500" />}
        valueClassName="text-green-500"
        trend="No vulnerabilities"
      />
      <Card
        title="Tỷ lệ lỗ hổng"
        value={ratio}
        icon={<Percent size={24} className="text-orange-400" />}
        valueClassName="text-orange-400"
        trend="Need attention"
      />
    </div>
  );
};

interface CardProps {
  title: string;
  value: string;
  icon: React.ReactNode;
  valueClassName?: string;
  trend?: string;
}

const Card: React.FC<CardProps> = ({ title, value, icon, valueClassName, trend }) => {
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden group">
      <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity group-hover:scale-110 transform duration-300">
        {icon}
      </div>
      <div className="flex justify-between items-start mb-4">
        <h3 className="text-slate-600 font-medium text-sm">{title}</h3>
        <div className="p-2 bg-slate-100/50 rounded-lg">{icon}</div>
      </div>
      <div className="flex flex-col">
        <span className={cn("text-3xl font-bold tracking-tight", valueClassName || "text-slate-900")}>
          {value}
        </span>
        {trend && (
          <span className="text-xs text-slate-500 mt-2 font-medium">
            {trend}
          </span>
        )}
      </div>
    </div>
  );
};

export default SummaryCards;
