"""
File Manager
============
Gestión inteligente de archivos físicos de respaldo.

Características:
- Retención por tiempo, cantidad y tamaño
- Compresión automática de archivos antiguos
- Verificación de integridad con BD
- Limpieza automatizada

Autor: Scan Agent Team
Versión: 1.0.0
"""

from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
import json
import shutil
import tarfile
import hashlib
import logging

logger = logging.getLogger(__name__)


class FileRetentionManager:
    """Gestiona la retención y limpieza de archivos de escaneo"""
    
    def __init__(self, config_path: str = "./storage_config.json"):
        """
        Inicializa el gestor de retención.
        
        Args:
            config_path: Ruta al archivo de configuración
        """
        self.config = self._load_config(config_path)
        self.base_dir = Path(self.config['storage']['base_dir'])
        self.active_dir = self.base_dir / "active"
        self.archived_dir = self.base_dir / "archived"
        self.metadata_dir = self.base_dir / "metadata"
        self.temp_dir = self.base_dir / "temp"
        
        # Crear directorios si no existen
        for directory in [self.active_dir, self.archived_dir, self.metadata_dir, self.temp_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self, config_path: str) -> dict:
        """Carga configuración desde archivo JSON"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return self._default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self._default_config()
    
    def _default_config(self) -> dict:
        """Configuración por defecto"""
        base_dir = str(Path(__file__).parent.parent.parent / "data" / "storage")
        return {
            "retention": {"default_policy": "standard", "enable_auto_cleanup": True},
            "storage": {"base_dir": base_dir, "max_size_gb": 20, "archive_threshold_days": 7, "delete_threshold_days": 90},
            "policies": {
                "standard": {"active_days": 7, "archived_days": 30, "delete_after_days": 90}
            },
            "quotas": {"max_active_scans": 1000, "max_archived_scans": 5000}
        }
    
    def save_scan_metadata(self, scan_id: str, metadata: dict) -> None:
        """
        Guarda metadata de un escaneo.
        
        Args:
            scan_id: ID del escaneo
            metadata: Diccionario con metadata
        """
        metadata_file = self.metadata_dir / f"{scan_id}.json"
        metadata['last_updated'] = datetime.now().isoformat()
        
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ Metadata guardada: {scan_id}")
    
    def load_scan_metadata(self, scan_id: str) -> Optional[dict]:
        """Carga metadata de un escaneo"""
        metadata_file = self.metadata_dir / f"{scan_id}.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading metadata for {scan_id}: {e}")
        return None
    
    def get_all_metadata(self) -> List[dict]:
        """Obtiene metadata de todos los escaneos"""
        metadata_list = []
        for metadata_file in self.metadata_dir.glob("*.json"):
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
                    metadata_list.append(metadata)
            except Exception as e:
                logger.error(f"Error loading {metadata_file}: {e}")
        return metadata_list
    
    def cleanup_old_files(self) -> Dict[str, int]:
        """
        Limpia archivos según políticas de retención.
        
        Returns:
            Estadísticas de limpieza
        """
        stats = {
            "deleted_by_age": 0,
            "archived": 0,
            "deleted_by_count": 0,
            "deleted_by_size": 0,
            "total_freed_mb": 0
        }
        
        logger.info("🧹 Iniciando limpieza de archivos...")
        
        # 1. Archivar escaneos antiguos
        stats["archived"] = self._archive_old_scans()
        
        # 2. Eliminar por antigüedad
        stats["deleted_by_age"] = self._cleanup_by_age()
        
        # 3. Eliminar por cantidad
        stats["deleted_by_count"] = self._cleanup_by_count()
        
        # 4. Eliminar por tamaño
        stats["deleted_by_size"] = self._cleanup_by_size()
        
        logger.info(f"✅ Limpieza completada: {stats}")
        return stats
    
    def _archive_old_scans(self) -> int:
        """Comprime escaneos que superan el umbral de archivado"""
        archived_count = 0
        archive_threshold = self.config['storage']['archive_threshold_days']
        cutoff_date = datetime.now() - timedelta(days=archive_threshold)
        
        metadata_list = self.get_all_metadata()
        
        for metadata in metadata_list:
            try:
                if metadata.get('status') != 'active':
                    continue
                
                scan_date = datetime.fromisoformat(metadata['created_at'])
                
                if scan_date < cutoff_date:
                    scan_id = metadata['scan_id']
                    if self._archive_scan(scan_id):
                        archived_count += 1
                        logger.info(f"   📦 Archivado: {scan_id}")
            except Exception as e:
                logger.error(f"Error archiving scan: {e}")
        
        return archived_count
    
    def _archive_scan(self, scan_id: str) -> bool:
        """
        Comprime un escaneo en .tar.gz y mueve a archived/
        
        Args:
            scan_id: ID del escaneo
            
        Returns:
            True si se archivó exitosamente
        """
        try:
            # Rutas
            outputs_dir = self.active_dir / "outputs" / f"scan_{scan_id}"
            reports_dir = self.active_dir / "reports"
            
            # Crear directorio archivado por año-mes
            archive_date = datetime.now()
            archive_subdir = self.archived_dir / f"{archive_date.year}-{archive_date.month:02d}"
            archive_subdir.mkdir(parents=True, exist_ok=True)
            
            archive_path = archive_subdir / f"scan_{scan_id}.tar.gz"
            
            # Crear archivo comprimido
            with tarfile.open(archive_path, "w:gz") as tar:
                # Agregar outputs si existen
                if outputs_dir.exists():
                    tar.add(outputs_dir, arcname=f"outputs/scan_{scan_id}")
                
                # Agregar reportes
                for report_file in reports_dir.glob(f"scan_{scan_id}.*"):
                    tar.add(report_file, arcname=f"reports/{report_file.name}")
            
            # Eliminar archivos originales
            if outputs_dir.exists():
                shutil.rmtree(outputs_dir)
            
            for report_file in reports_dir.glob(f"scan_{scan_id}.*"):
                report_file.unlink()
            
            # Actualizar metadata
            metadata = self.load_scan_metadata(scan_id)
            if metadata:
                metadata['status'] = 'archived'
                metadata['archived_path'] = str(archive_path)
                metadata['archived_at'] = datetime.now().isoformat()
                self.save_scan_metadata(scan_id, metadata)
            
            return True
            
        except Exception as e:
            logger.error(f"Error archiving {scan_id}: {e}")
            return False
    
    def _cleanup_by_age(self) -> int:
        """Elimina archivos archivados que superan el umbral de eliminación"""
        deleted_count = 0
        delete_threshold = self.config['storage']['delete_threshold_days']
        cutoff_date = datetime.now() - timedelta(days=delete_threshold)
        
        metadata_list = self.get_all_metadata()
        
        for metadata in metadata_list:
            try:
                if metadata.get('status') != 'archived':
                    continue
                
                scan_date = datetime.fromisoformat(metadata['created_at'])
                
                if scan_date < cutoff_date:
                    scan_id = metadata['scan_id']
                    if self._delete_scan(scan_id):
                        deleted_count += 1
                        logger.info(f"   🗑️  Eliminado por antigüedad: {scan_id}")
            except Exception as e:
                logger.error(f"Error deleting scan: {e}")
        
        return deleted_count
    
    def _cleanup_by_count(self) -> int:
        """Elimina escaneos más antiguos si se supera el máximo"""
        deleted_count = 0
        max_archived = self.config['quotas']['max_archived_scans']
        
        # Obtener todos los archivados
        archived_metadata = [m for m in self.get_all_metadata() if m.get('status') == 'archived']
        
        if len(archived_metadata) <= max_archived:
            return 0
        
        # Ordenar por fecha (más antiguos primero)
        archived_metadata.sort(key=lambda x: x['created_at'])
        
        # Eliminar excedentes
        to_delete = len(archived_metadata) - max_archived
        for metadata in archived_metadata[:to_delete]:
            try:
                scan_id = metadata['scan_id']
                if self._delete_scan(scan_id):
                    deleted_count += 1
                    logger.info(f"   🗑️  Eliminado por límite de cantidad: {scan_id}")
            except Exception as e:
                logger.error(f"Error deleting {scan_id}: {e}")
        
        return deleted_count
    
    def _cleanup_by_size(self) -> int:
        """Elimina archivos si se supera el límite de tamaño total"""
        deleted_count = 0
        max_size_gb = self.config['storage']['max_size_gb']
        max_size_bytes = max_size_gb * 1024 * 1024 * 1024
        
        # Calcular tamaño total
        total_size = self._calculate_total_size()
        
        if total_size <= max_size_bytes:
            return 0
        
        logger.info(f"   ⚠️  Tamaño total ({total_size / (1024**3):.2f} GB) excede límite ({max_size_gb} GB)")
        
        # Obtener archivados ordenados por tamaño (más grandes primero)
        archived_metadata = [m for m in self.get_all_metadata() if m.get('status') == 'archived']
        archived_metadata.sort(key=lambda x: x.get('size_bytes', 0), reverse=True)
        
        # Eliminar hasta estar bajo el límite
        for metadata in archived_metadata:
            if total_size <= max_size_bytes:
                break
            
            try:
                scan_id = metadata['scan_id']
                scan_size = metadata.get('size_bytes', 0)
                
                if self._delete_scan(scan_id):
                    total_size -= scan_size
                    deleted_count += 1
                    logger.info(f"   🗑️  Eliminado por tamaño: {scan_id} ({scan_size / (1024**2):.2f} MB)")
            except Exception as e:
                logger.error(f"Error deleting {scan_id}: {e}")
        
        return deleted_count
    
    def _delete_scan(self, scan_id: str) -> bool:
        """
        Elimina completamente un escaneo (archivos y metadata).
        
        Args:
            scan_id: ID del escaneo
            
        Returns:
            True si se eliminó exitosamente
        """
        try:
            metadata = self.load_scan_metadata(scan_id)
            if not metadata:
                return False
            
            # Eliminar archivo archivado si existe
            if 'archived_path' in metadata:
                archived_path = Path(metadata['archived_path'])
                if archived_path.exists():
                    archived_path.unlink()
            
            # Eliminar metadata
            metadata_file = self.metadata_dir / f"{scan_id}.json"
            if metadata_file.exists():
                metadata_file.unlink()
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting {scan_id}: {e}")
            return False
    
    def _calculate_total_size(self) -> int:
        """Calcula el tamaño total ocupado por todos los archivos"""
        total_size = 0
        
        # Archivos activos
        for item in self.active_dir.rglob("*"):
            if item.is_file():
                total_size += item.stat().st_size
        
        # Archivos archivados
        for item in self.archived_dir.rglob("*.tar.gz"):
            total_size += item.stat().st_size
        
        return total_size
    
    def get_storage_stats(self) -> Dict:
        """Obtiene estadísticas de almacenamiento"""
        metadata_list = self.get_all_metadata()
        
        active_scans = [m for m in metadata_list if m.get('status') == 'active']
        archived_scans = [m for m in metadata_list if m.get('status') == 'archived']
        
        total_size = self._calculate_total_size()
        
        return {
            "total_size_mb": total_size / (1024 * 1024),
            "total_size_gb": total_size / (1024 * 1024 * 1024),
            "total_scans": len(metadata_list),
            "active_scans": len(active_scans),
            "archived_scans": len(archived_scans),
            "oldest_scan": min([m['created_at'] for m in metadata_list]) if metadata_list else None,
            "newest_scan": max([m['created_at'] for m in metadata_list]) if metadata_list else None,
            "max_size_gb": self.config['storage']['max_size_gb'],
            "usage_percent": (total_size / (self.config['storage']['max_size_gb'] * 1024**3)) * 100
        }
