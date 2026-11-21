import React from 'react';
import { Header } from './landing/Header';

interface NavbarProps {
  onOpenStandardsModal: () => void;
  onOpenExportModal: () => void;
  hasScanData: boolean;
  backendOnline: boolean;
  activeView: 'scanner' | 'catalog' | 'risk' | 'simulator' | 'upgrade-plan';
  onSelectView: (
    view: 'scanner' | 'catalog' | 'risk' | 'simulator' | 'upgrade-plan'
  ) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  onOpenStandardsModal,
  onOpenExportModal,
  hasScanData,
  activeView,
  onSelectView,
}) => {
  return (
    <Header
      activeView={activeView}
      onSelectView={onSelectView}
      onOpenDocumentation={onOpenStandardsModal}
      onOpenExportModal={onOpenExportModal}
      hasScanData={hasScanData}
    />
  );
};

export default Navbar;
