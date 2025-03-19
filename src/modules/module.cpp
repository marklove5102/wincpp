#include "wincpp/modules/module.hpp"

#include <algorithm>

#include "wincpp/modules/object.hpp"
#include "wincpp/modules/section.hpp"
#include "wincpp/patterns/scanner.hpp"
#include "wincpp/process.hpp"

namespace wincpp::modules
{
    module_t::module_t( const memory_factory &factory, const core::module_entry_t &entry ) noexcept
        : memory_t( factory, entry.base_address, entry.base_size ),
          entry( entry ),
          info(),
          _sections(),
          _exports()
    {
        GetModuleInformation( factory.p->handle->native, reinterpret_cast< HMODULE >( entry.base_address ), &info, sizeof( info ) );

        // Read the first page of the module.
        buffer = read( 0x0, 0x1000 );

        // Get the DOS header.
        dos_header = reinterpret_cast< const IMAGE_DOS_HEADER * >( buffer.get() );

        // Get the NT headers.
        nt_headers = reinterpret_cast< const IMAGE_NT_HEADERS * >( buffer.get() + dos_header->e_lfanew );
    }

    std::string_view module_t::name() const noexcept
    {
        return entry.name;
    }

    std::uintptr_t module_t::entry_point() const noexcept
    {
        return reinterpret_cast< std::uintptr_t >( info.EntryPoint );
    }

    std::string module_t::path() const noexcept
    {
        return entry.path;
    }

    const std::list< std::shared_ptr< module_t::export_t > > &module_t::exports() const noexcept
    {
        // Populate the export list.
        if ( _exports.empty() )
        {
            const auto directory_header = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

            if ( directory_header.VirtualAddress )
            {
                // Refresh the buffer.
                const auto expbuffer = read( directory_header.VirtualAddress, directory_header.Size );

                // Define the RVA to offset helper.
                const auto rva_to_offset = [ directory_header ]( std::uintptr_t rva ) -> std::uintptr_t
                { return rva - directory_header.VirtualAddress; };

                const auto export_directory =
                    reinterpret_cast< const IMAGE_EXPORT_DIRECTORY * >( expbuffer.get() + rva_to_offset( directory_header.VirtualAddress ) );

                const auto names = reinterpret_cast< const std::uint32_t * >( expbuffer.get() + rva_to_offset( export_directory->AddressOfNames ) );
                const auto ordinals =
                    reinterpret_cast< const std::uint16_t * >( expbuffer.get() + rva_to_offset( export_directory->AddressOfNameOrdinals ) );
                const auto functions =
                    reinterpret_cast< const std::uint32_t * >( expbuffer.get() + rva_to_offset( export_directory->AddressOfFunctions ) );

                for ( std::uint32_t i = 0; i < export_directory->NumberOfNames; ++i )
                {
                    const auto ordinal = ordinals[ i ];
                    const auto address = functions[ ordinal ];

                    const auto name = reinterpret_cast< const char * >( expbuffer.get() + rva_to_offset( names[ i ] ) );

                    // Check if the address is forwarded.
                    if ( address >= directory_header.VirtualAddress && address < directory_header.VirtualAddress + directory_header.Size )
                    {
                        const std::string forward = reinterpret_cast< const char * >( expbuffer.get() + rva_to_offset( address ) );

                        // Get the module name and the export name.
                        const auto dot = forward.find( '.' );
                        const auto module_name = forward.substr( 0, dot );
                        const auto export_name = forward.substr( dot + 1 );

                        const auto &m = factory.p->module_factory.fetch_module( module_name );

                        if ( !m )
                            continue;

                        const auto &exp = m->fetch_export( export_name );

                        if ( !exp )
                            continue;

                        _exports.emplace_back( new export_t{ exp->module(), name, exp->rva, exp->ordinal() } );
                        continue;
                    }

                    _exports.emplace_back( new export_t( shared_from_this(), name, address, ordinals[ i ] ) );
                }
            }
        }

        return _exports;
    }

    std::shared_ptr< module_t::export_t > module_t::fetch_export( const std::string_view name ) const
    {
        for ( const auto &e : exports() )
        {
            if ( e->name() == name )
                return e;
        }

        return nullptr;
    }

    const std::list< std::shared_ptr< module_t::section_t > > &module_t::sections() const noexcept
    {
        // Populate the sections list.
        if ( _sections.empty() )
        {
            const auto section = IMAGE_FIRST_SECTION( nt_headers );

            for ( std::uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i )
            {
                _sections.emplace_back( new section_t( shared_from_this(), section[ i ] ) );
            }
        }

        return _sections;
    }

    std::shared_ptr< module_t::section_t > module_t::fetch_section( const std::string_view name ) const
    {
        for ( const auto &s : sections() )
        {
            if ( s->name() == name )
                return s;
        }

        return nullptr;
    }

    std::vector< std::shared_ptr< rtti::object_t > > module_t::fetch_objects( const std::string_view mangled ) const
    {
        std::vector< std::shared_ptr< rtti::object_t > > objects;

        // Get the sections that we need for location.
        const auto &data = fetch_section( ".data" );
        const auto &rdata = fetch_section( ".rdata" );

        if ( !data || !rdata )
            return {};

        const auto result = data->find( mangled );

        if ( !result )
            return {};

        // Calculate the type descriptor address based on the match for the string.
        const auto type_descriptor_address = *result - sizeof( std::uintptr_t ) * 2;
        const auto type_descriptor_rva = static_cast< std::int32_t >( type_descriptor_address - address() );

        // Find all cross references to the type descriptor in the .rdata section.
        const auto cross_references = rdata->find_all( type_descriptor_rva );

        for ( const auto &reference : cross_references )
        {
            const auto col_address = reference - sizeof( std::uint32_t ) * 3;

            // Now we read the complete object locator and check if its valid.
            const auto col = factory.read< rtti::complete_object_locator_t >( col_address );

            if ( col.signature != 1 )
                continue;

            // Now we know that we've located a valid object. Now we need to locate the vtable address associated with the current complete object
            // locator.
            const auto col_reference = rdata->find( col_address );

            if ( !col_reference )
                continue;

            objects.emplace_back( new rtti::object_t( this, *col_reference + sizeof( std::uintptr_t ), col ) );
        }

        return objects;
    }

    const module_t::export_t &module_t::operator[]( const std::string_view name ) const
    {
        if ( const auto result = fetch_export( name ) )
            return *result;

        throw core::error::from_user(
            core::user_error_type_t::export_not_found_t, "Failed to find export \"{}\" in module \"{}\"", name, this->name() );
    }
}  // namespace wincpp::modules